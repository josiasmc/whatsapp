// mautrix-whatsapp - A Matrix-WhatsApp puppeting bridge.
// Copyright (C) 2021 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/tidwall/gjson"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/appstate"
	"go.mau.fi/whatsmeow/types"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type WrappedCommandEvent struct {
	*commands.Event
	Bridge *WABridge
	User   *User
	Portal *Portal
}

func (br *WABridge) RegisterCommands() {
	proc := br.CommandProcessor.(*commands.Processor)
	proc.AddHandlers(
		cmdSetRelay,
		cmdUnsetRelay,
		cmdInviteLink,
		cmdResolveLink,
		cmdJoin,
		cmdAccept,
		cmdCreate,
		cmdLogin,
		cmdLogout,
		cmdTogglePresence,
		cmdDeleteSession,
		cmdReconnect,
		cmdDisconnect,
		cmdPing,
		cmdDeletePortal,
		cmdDeleteAllPortals,
		cmdList,
		cmdSearch,
		cmdOpen,
		cmdPM,
		cmdSync,
		cmdDisappearingTimer,
	)
}

func wrapCommand(handler func(*WrappedCommandEvent)) func(*commands.Event) {
	return func(ce *commands.Event) {
		user := ce.User.(*User)
		var portal *Portal
		if ce.Portal != nil {
			portal = ce.Portal.(*Portal)
		}
		br := ce.Bridge.Child.(*WABridge)
		handler(&WrappedCommandEvent{ce, br, user, portal})
	}
}

var (
	HelpSectionConnectionManagement = commands.HelpSection{Name: "Manejar conexiones", Order: 11}
	HelpSectionCreatingPortals      = commands.HelpSection{Name: "Creando portales", Order: 15}
	HelpSectionPortalManagement     = commands.HelpSection{Name: "Manejar portales", Order: 20}
	HelpSectionInvites              = commands.HelpSection{Name: "Invitaciones de grupo", Order: 25}
	HelpSectionMiscellaneous        = commands.HelpSection{Name: "Misceláneo", Order: 30}
)

var cmdSetRelay = &commands.FullHandler{
	Func: wrapCommand(fnSetRelay),
	Name: "activar-retransmision",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Retransmitir mensajes en esta sala mediante su cuenta de WhatsApp.",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
}

func fnSetRelay(ce *WrappedCommandEvent) {
	if !ce.Bridge.Config.Bridge.Relay.Enabled {
		ce.Reply("Retransmisión no está activado en esta instancia del puente")
	} else if ce.Bridge.Config.Bridge.Relay.AdminOnly && !ce.User.Admin {
		ce.Reply("Solo administradores tienen autorización para activar retransmisión en esta instancia del puente")
	} else {
		ce.Portal.RelayUserID = ce.User.MXID
		ce.Portal.Update(nil)
		ce.Reply("Mensajes de usuarios que no tienen sesión iniciada en WhatsApp ahora serán enviados por medio de su cuenta de WhatsApp")
	}
}

var cmdUnsetRelay = &commands.FullHandler{
	Func: wrapCommand(fnUnsetRelay),
	Name: "desactivar-retransmision",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Parar de retransmitir mensajes en esta sala.",
	},
	RequiresPortal: true,
}

func fnUnsetRelay(ce *WrappedCommandEvent) {
	if !ce.Bridge.Config.Bridge.Relay.Enabled {
		ce.Reply("Retransmisión no está activado en esta instancia del puente")
	} else if ce.Bridge.Config.Bridge.Relay.AdminOnly && !ce.User.Admin {
		ce.Reply("Solo administradores tienen autorización para desactivar retransmisión en esta instancia del puente")
	} else {
		ce.Portal.RelayUserID = ""
		ce.Portal.Update(nil)
		ce.Reply("Mensajes de usuarios que no tienen sesión iniciada en WhatsApp ahora dejarán de enviados por medio de su cuenta de WhatsApp")
	}
}

var cmdInviteLink = &commands.FullHandler{
	Func: wrapCommand(fnInviteLink),
	Name: "enlace-de-invitacion",
	Help: commands.HelpMeta{
		Section:     HelpSectionInvites,
		Description: "Conseguir un enlace de invitación al grupo actual, opcionalmente regenerando el enlace y revocando el enlace viejo.",
		Args:        "[--restablecer]",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
}

func fnInviteLink(ce *WrappedCommandEvent) {
	reset := len(ce.Args) > 0 && strings.ToLower(ce.Args[0]) == "--restablecer"
	if ce.Portal.IsPrivateChat() {
		ce.Reply("No se puede conseguir un enlace de invitación al chat directo")
	} else if ce.Portal.IsBroadcastList() {
		ce.Reply("No se puede conseguir un enlace de invitación a una difusión")
	} else if link, err := ce.User.Client.GetGroupInviteLink(ce.Portal.Key.JID, reset); err != nil {
		ce.Reply("No se pudo conseguir el enlace de invitación: %v", err)
	} else {
		ce.Reply(link)
	}
}

var cmdResolveLink = &commands.FullHandler{
	Func: wrapCommand(fnResolveLink),
	Name: "resolver-enlace",
	Help: commands.HelpMeta{
		Section:     HelpSectionInvites,
		Description: "Resolver una invitación a un grupo de WhatsApp o a un enlace a mensaje de negocio.",
		Args:        "<_grupo, contacto, o enlace de mensaje_>",
	},
	RequiresLogin: true,
}

func fnResolveLink(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Uso:** `resolver-enlace <enlace de grupo o de mensaje>`")
		return
	}
	if strings.HasPrefix(ce.Args[0], whatsmeow.InviteLinkPrefix) {
		group, err := ce.User.Client.GetGroupInfoFromLink(ce.Args[0])
		if err != nil {
			ce.Reply("Ocurrió un falla al conseguir la información del grupo: %v", err)
			return
		}
		ce.Reply("Ese enlace de invitación apunta a %s (`%s`)", group.Name, group.JID)
	} else if strings.HasPrefix(ce.Args[0], whatsmeow.BusinessMessageLinkPrefix) || strings.HasPrefix(ce.Args[0], whatsmeow.BusinessMessageLinkDirectPrefix) {
		target, err := ce.User.Client.ResolveBusinessMessageLink(ce.Args[0])
		if err != nil {
			ce.Reply("Ocurrió un fallo al conseguir la información del negocio: %v", err)
			return
		}
		message := ""
		if len(target.Message) > 0 {
			parts := strings.Split(target.Message, "\n")
			for i, part := range parts {
				parts[i] = "> " + html.EscapeString(part)
			}
			message = fmt.Sprintf(" El siguiente mensaje prellenado está adjuntado:\n\n%s", strings.Join(parts, "\n"))
		}
		ce.Reply("Ése enlace apunta a %s (+%s).%s", target.PushName, target.JID.User, message)
	} else if strings.HasPrefix(ce.Args[0], whatsmeow.ContactQRLinkPrefix) || strings.HasPrefix(ce.Args[0], whatsmeow.ContactQRLinkDirectPrefix) {
		target, err := ce.User.Client.ResolveContactQRLink(ce.Args[0])
		if err != nil {
			ce.Reply("Ocurrió un fallo al conseguir la información del contacto: %v", err)
			return
		}
		if target.PushName != "" {
			ce.Reply("Ése enlace apunta a %s (+%s)", target.PushName, target.JID.User)
		} else {
			ce.Reply("Ése enlace apunta a +%s", target.JID.User)
		}
	} else {
		ce.Reply("Eso no se mira como una invitación a un grupo ni a un enalce a mensaje de negocio.")
	}
}

var cmdJoin = &commands.FullHandler{
	Func: wrapCommand(fnJoin),
	Name: "unirme",
	Help: commands.HelpMeta{
		Section:     HelpSectionInvites,
		Description: "Unirse a un chat de grupo con un enlace de invitación.",
		Args:        "<_enlace de invitación_>",
	},
	RequiresLogin: true,
}

func fnJoin(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Uso:** `unirme <enlace de invitación>`")
		return
	}

	if strings.HasPrefix(ce.Args[0], whatsmeow.InviteLinkPrefix) {
		jid, err := ce.User.Client.JoinGroupWithLink(ce.Args[0])
		if err != nil {
			ce.Reply("Fallo al unirse al grupo: %v", err)
			return
		}
		ce.Log.Debugln("%s successfully joined group %s", ce.User.MXID, jid)
		ce.Reply("Te has unido exitosamente al grupo `%s`, el portal será creado en breve", jid)
	} else if strings.HasPrefix(ce.Args[0], whatsmeow.NewsletterLinkPrefix) {
		info, err := ce.User.Client.GetNewsletterInfoWithInvite(ce.Args[0])
		if err != nil {
			ce.Reply("Fallo al conseguir la información del canal: %v", err)
			return
		}
		err = ce.User.Client.FollowNewsletter(info.ID)
		if err != nil {
			ce.Reply("Fallo al seguir el canal: %v", err)
			return
		}
		ce.Log.Debugln("%s successfully followed channel %s", ce.User.MXID, info.ID)
		ce.Reply("Has comenzado a seguir el canal `%s`, el portal será creado en breve", info.ID)
	} else {
		ce.Reply("Eso no se mira como un enlace de invitación a WhatsApp")
	}
}

func tryDecryptEvent(crypto bridge.Crypto, evt *event.Event) (json.RawMessage, error) {
	var data json.RawMessage
	if evt.Type != event.EventEncrypted {
		data = evt.Content.VeryRaw
	} else {
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil && !errors.Is(err, event.ErrContentAlreadyParsed) {
			return nil, err
		}
		decrypted, err := crypto.Decrypt(evt)
		if err != nil {
			return nil, err
		}
		data = decrypted.Content.VeryRaw
	}
	return data, nil
}

func parseInviteMeta(data json.RawMessage) (*InviteMeta, error) {
	result := gjson.GetBytes(data, escapedInviteMetaField)
	if !result.Exists() || !result.IsObject() {
		return nil, nil
	}
	var meta InviteMeta
	err := json.Unmarshal([]byte(result.Raw), &meta)
	if err != nil {
		return nil, nil
	}
	return &meta, nil
}

var cmdAccept = &commands.FullHandler{
	Func: wrapCommand(fnAccept),
	Name: "aceptar",
	Help: commands.HelpMeta{
		Section:     HelpSectionInvites,
		Description: "Aceptar un mensaje a un grupo. Solamente se puede usar en respuesta a un mensaje de invitación de grupo",
	},
	RequiresLogin:  true,
	RequiresPortal: true,
}

func fnAccept(ce *WrappedCommandEvent) {
	if len(ce.ReplyTo) == 0 {
		ce.Reply("Debes responder a un mensaje de invitación de grupo al usar este comando.")
	} else if evt, err := ce.Portal.MainIntent().GetEvent(ce.RoomID, ce.ReplyTo); err != nil {
		ce.Log.Errorln("Failed to get event %s to handle !wa accept command: %v", ce.ReplyTo, err)
		ce.Reply("Ocurrió un fallo al coger el evento de respuesta")
	} else if rawContent, err := tryDecryptEvent(ce.Bridge.Crypto, evt); err != nil {
		ce.Log.Errorln("Failed to decrypt event %s to handle !wa accept command: %v", ce.ReplyTo, err)
		ce.Reply("Ocurrió un fallo al descifrar el evento de respuesta")
	} else if meta, err := parseInviteMeta(rawContent); err != nil || meta == nil {
		ce.Reply("Eso no se mira como un mensaje de invitación de grupo.")
	} else if meta.Inviter.User == ce.User.JID.User {
		ce.Reply("No puedes aceptar tus propias invitaciones")
	} else if err = ce.User.Client.JoinGroupWithInvite(meta.JID, meta.Inviter, meta.Code, meta.Expiration); err != nil {
		ce.Reply("Ocurrió un fallo al aceptar la invitación al grupo: %v", err)
	} else {
		ce.Reply("La invitación se aceptó exitosamente. El portal será creado en breve.")
	}
}

var cmdCreate = &commands.FullHandler{
	Func: wrapCommand(fnCreate),
	Name: "crear",
	Help: commands.HelpMeta{
		Section:     HelpSectionCreatingPortals,
		Description: "Crear un grupo WhatsApp para la sala actual de Matrix.",
	},
	RequiresLogin: true,
}

func fnCreate(ce *WrappedCommandEvent) {
	if ce.Portal != nil {
		ce.Reply("Esta ya es una sala de portal")
		return
	}

	members, err := ce.Bot.JoinedMembers(ce.RoomID)
	if err != nil {
		ce.Reply("Ocurrió un fallo al conseguir los miembros de la sala: %v", err)
		return
	}

	var roomNameEvent event.RoomNameEventContent
	err = ce.Bot.StateEvent(ce.RoomID, event.StateRoomName, "", &roomNameEvent)
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		ce.Log.Errorln("Failed to get room name to create group:", err)
		ce.Reply("Ocurrió un fallo al conseguir el nombre de la sala")
		return
	} else if len(roomNameEvent.Name) == 0 {
		ce.Reply("Por favor establezca un nombre para la sala primero")
		return
	}

	var encryptionEvent event.EncryptionEventContent
	err = ce.Bot.StateEvent(ce.RoomID, event.StateEncryption, "", &encryptionEvent)
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		ce.Reply("Ocurrió un fallo al conseguir el estado de cifrado de la sala")
		return
	}

	var createEvent event.CreateEventContent
	err = ce.Bot.StateEvent(ce.RoomID, event.StateCreate, "", &createEvent)
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		ce.Reply("Failed to get room create event")
		return
	}

	var participants []types.JID
	participantDedup := make(map[types.JID]bool)
	participantDedup[ce.User.JID.ToNonAD()] = true
	participantDedup[types.EmptyJID] = true
	for userID := range members.Joined {
		jid, ok := ce.Bridge.ParsePuppetMXID(userID)
		if !ok {
			user := ce.Bridge.GetUserByMXID(userID)
			if user != nil && !user.JID.IsEmpty() {
				jid = user.JID.ToNonAD()
			}
		}
		if !participantDedup[jid] {
			participantDedup[jid] = true
			participants = append(participants, jid)
		}
	}
	// TODO check m.space.parent to create rooms directly in communities

	messageID := ce.User.Client.GenerateMessageID()
	ce.Log.Infofln("Creando grupo para %s con el nombre %s y los participantes %+v (crear llave: %s)", ce.RoomID, roomNameEvent.Name, participants, messageID)
	ce.User.createKeyDedup = messageID
	resp, err := ce.User.Client.CreateGroup(whatsmeow.ReqCreateGroup{
		CreateKey:    messageID,
		Name:         roomNameEvent.Name,
		Participants: participants,
		GroupParent: types.GroupParent{
			IsParent: createEvent.Type == event.RoomTypeSpace,
		},
	})
	if err != nil {
		ce.Reply("No se pudo crear el grupo: %v", err)
		return
	}
	portal := ce.User.GetPortalByJID(resp.JID)
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if len(portal.MXID) != 0 {
		portal.log.Warnln("Detected race condition in room creation")
		// TODO race condition, clean up the old room
	}
	portal.MXID = ce.RoomID
	portal.Name = roomNameEvent.Name
	portal.IsParent = resp.IsParent
	portal.Encrypted = encryptionEvent.Algorithm == id.AlgorithmMegolmV1
	if !portal.Encrypted && ce.Bridge.Config.Bridge.Encryption.Default {
		_, err = portal.MainIntent().SendStateEvent(portal.MXID, event.StateEncryption, "", portal.GetEncryptionEventContent())
		if err != nil {
			portal.log.Warnln("Failed to enable encryption in room:", err)
			if errors.Is(err, mautrix.MForbidden) {
				ce.Reply("Parece que no tengo permiso para habilitar el cifrado en esta sala.")
			} else {
				ce.Reply("No se pudo habilitar el cifrado en la sala: %v", err)
			}
		}
		portal.Encrypted = true
	}

	portal.Update(nil)
	portal.UpdateBridgeInfo()
	ce.User.createKeyDedup = ""

	ce.Reply("El grupo de WhatsApp se creó exitosamente %s", portal.Key.JID)
}

var cmdLogin = &commands.FullHandler{
	Func: wrapCommand(fnLogin),
	Name: "iniciar-sesion",
	Help: commands.HelpMeta{
		Section: commands.HelpSectionAuth,
		Description: "Vincular el puente a su cuenta de WhatsApp como un cliente web." +
			"El parámetro del número de teléfono es opcional: si se provee, el puente creará un código de 8 carácteres " +
			"que se puede usar en lugar de un código QR.",
		Args: "[_número de teléfono_]",
	},
}

var looksLikeAPhoneRegex = regexp.MustCompile(`^\+[0-9]+$`)

func fnLogin(ce *WrappedCommandEvent) {
	if ce.User.Session != nil {
		if ce.User.IsConnected() {
			ce.Reply("Ya tienes sesión iniciada")
		} else {
			ce.Reply("Ya tienes sesión iniciada. Tal vez lo que quieres es `reconectar`?")
		}
		return
	}

	var phoneNumber string
	if len(ce.Args) > 0 {
		phoneNumber = strings.TrimSpace(strings.Join(ce.Args, " "))
		if !looksLikeAPhoneRegex.MatchString(phoneNumber) {
			ce.Reply("When specifying a phone number, it must be provided in international format without spaces or other extra characters")
			return
		}
	}

	qrChan, err := ce.User.Login(context.Background())
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to start login")
		ce.Reply("No se pudo iniciar sesión: %v", err)
		return
	}

	if phoneNumber != "" {
		pairingCode, err := ce.User.Client.PairPhone(phoneNumber, true, whatsmeow.PairClientChrome, "Chrome (Linux)")
		if err != nil {
			ce.ZLog.Err(err).Msg("Failed to start phone code login")
			ce.Reply("Failed to start phone code login: %v", err)
			go ce.User.DeleteConnection()
			return
		}
		ce.Reply("Scan the code below or enter the following code on your phone to log in: **%s**", pairingCode)
	}

	var qrEventID id.EventID
	for item := range qrChan {
		switch item.Event {
		case whatsmeow.QRChannelSuccess.Event:
			jid := ce.User.Client.Store.ID
			ce.Reply("Sesión iniciada exitosamente como +%s (dispositivo #%d)", jid.User, jid.Device)
		case whatsmeow.QRChannelTimeout.Event:
			ce.Reply("El inicio de sesión expiró. Por favor vuelva a comenzar el inicio de sesión.")
		case whatsmeow.QRChannelErrUnexpectedEvent.Event:
			ce.Reply("No se pudo iniciar sesión: un evento inesperado de conexión del servidor")
		case whatsmeow.QRChannelClientOutdated.Event:
			ce.Reply("No se pudo iniciar sesión: cliente desactualizado. El puente necesita ser actualizado para continuar.")
		case whatsmeow.QRChannelScannedWithoutMultidevice.Event:
			ce.Reply("Por favor habilite Versión beta para varios dispositivos y escanee el código QR de nuevo.")
		case "error":
			ce.Reply("No se pudo iniciar sesión: %v", item.Error)
		case "code":
			qrEventID = ce.User.sendQR(ce, item.Code, qrEventID)
		}
	}
	if qrEventID != "" {
		_, _ = ce.Bot.RedactEvent(ce.RoomID, qrEventID)
	}
}

func (user *User) sendQR(ce *WrappedCommandEvent, code string, prevEvent id.EventID) id.EventID {
	url, ok := user.uploadQR(ce, code)
	if !ok {
		return prevEvent
	}
	content := event.MessageEventContent{
		MsgType: event.MsgImage,
		Body:    code,
		URL:     url.CUString(),
	}
	if len(prevEvent) != 0 {
		content.SetEdit(prevEvent)
	}
	resp, err := ce.Bot.SendMessageEvent(ce.RoomID, event.EventMessage, &content)
	if err != nil {
		user.log.Errorln("Failed to send edited QR code to user:", err)
	} else if len(prevEvent) == 0 {
		prevEvent = resp.EventID
	}
	return prevEvent
}

func (user *User) uploadQR(ce *WrappedCommandEvent, code string) (id.ContentURI, bool) {
	qrCode, err := qrcode.Encode(code, qrcode.Low, 256)
	if err != nil {
		user.log.Errorln("Failed to encode QR code:", err)
		ce.Reply("No se pudo codificar el código QR: %v", err)
		return id.ContentURI{}, false
	}

	bot := user.bridge.AS.BotClient()

	resp, err := bot.UploadBytes(qrCode, "image/png")
	if err != nil {
		user.log.Errorln("Failed to upload QR code:", err)
		ce.Reply("No se pudo subir el código QR: %v", err)
		return id.ContentURI{}, false
	}
	return resp.ContentURI, true
}

var cmdLogout = &commands.FullHandler{
	Func: wrapCommand(fnLogout),
	Name: "cerrar-sesion",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Desvincular el puente de su cuenta de WhatsApp.",
	},
}

func fnLogout(ce *WrappedCommandEvent) {
	if ce.User.Session == nil {
		ce.Reply("No tienes sesión iniciada.")
		return
	} else if !ce.User.IsLoggedIn() {
		ce.Reply("No estás conectado a WhatsApp. Utilice el comando `reconectar` para reconectarse, o `eliminar-sesion` para olvidar toda la información de la sesión.")
		return
	}
	puppet := ce.Bridge.GetPuppetByJID(ce.User.JID)
	puppet.ClearCustomMXID()
	err := ce.User.Client.Logout()
	if err != nil {
		ce.User.log.Warnln("Error while logging out:", err)
		ce.Reply("Ocurrió un error desconocido al cerrar sesión: %v", err)
		return
	}
	ce.User.Session = nil
	ce.User.removeFromJIDMap(status.BridgeState{StateEvent: status.StateLoggedOut})
	ce.User.DeleteConnection()
	ce.User.DeleteSession()
	ce.Reply("Sesión cerrada exitosamente.")
}

var cmdTogglePresence = &commands.FullHandler{
	Func: wrapCommand(fnTogglePresence),
	Name: "alternar-presencia",
	Help: commands.HelpMeta{
		Section:     HelpSectionConnectionManagement,
		Description: "Alternar el envío de presencia y lecturas.",
	},
}

func fnTogglePresence(ce *WrappedCommandEvent) {
	if ce.User.Session == nil {
		ce.Reply("No tienes sesión iniciada.")
		return
	}
	customPuppet := ce.Bridge.GetPuppetByCustomMXID(ce.User.MXID)
	if customPuppet == nil {
		ce.Reply("No tienes sesión iniciada con su cuenta de Matrix.")
		return
	}
	customPuppet.EnablePresence = !customPuppet.EnablePresence
	var newPresence types.Presence
	if customPuppet.EnablePresence {
		newPresence = types.PresenceAvailable
		ce.Reply("Se habilitó el envío de presencia")
	} else {
		newPresence = types.PresenceUnavailable
		ce.Reply("Se deshabilitó el envío de presencia")
	}
	if ce.User.IsLoggedIn() {
		err := ce.User.Client.SendPresence(newPresence)
		if err != nil {
			ce.User.log.Warnln("No se pudo establecer el ajuste de presencia:", err)
		}
	}
	customPuppet.Update()
}

var cmdDeleteSession = &commands.FullHandler{
	Func: wrapCommand(fnDeleteSession),
	Name: "eliminar-sesion",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Eliminar la información de la sesión y desconectarse de WhatsApp sin enviar una petición de cerrar sesión.",
	},
}

func fnDeleteSession(ce *WrappedCommandEvent) {
	if ce.User.Session == nil && ce.User.Client == nil {
		ce.Reply("Nada que purgar: no hay información de sesión guardada ni una conexión activa.")
		return
	}
	ce.User.removeFromJIDMap(status.BridgeState{StateEvent: status.StateLoggedOut})
	ce.User.DeleteConnection()
	ce.User.DeleteSession()
	ce.Reply("Información de sesión purgada")
}

var cmdReconnect = &commands.FullHandler{
	Func: wrapCommand(fnReconnect),
	Name: "reconectar",
	Help: commands.HelpMeta{
		Section:     HelpSectionConnectionManagement,
		Description: "Reconectarse a WhatsApp.",
	},
}

func fnReconnect(ce *WrappedCommandEvent) {
	if ce.User.Client == nil {
		if ce.User.Session == nil {
			ce.Reply("No tienes sesión iniciada con WhatsApp. Por favor inicie sesión primero.")
		} else {
			ce.User.Connect()
			ce.Reply("Conexión a WhatsApp comenzada")
		}
	} else {
		ce.User.DeleteConnection()
		ce.User.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: WANotConnected})
		ce.User.Connect()
		ce.Reply("Reconexión a WhatsApp comenzada")
	}
}

var cmdDisconnect = &commands.FullHandler{
	Func: wrapCommand(fnDisconnect),
	Name: "desconectar",
	Help: commands.HelpMeta{
		Section:     HelpSectionConnectionManagement,
		Description: "Desconectarse de WhatsApp (sin cerrar sesión)",
	},
}

func fnDisconnect(ce *WrappedCommandEvent) {
	if ce.User.Client == nil {
		ce.Reply("No tienes una conexión con WhatsApp.")
		return
	}
	ce.User.DeleteConnection()
	ce.Reply("Desconectado exitosamente. Utilice el comando `reconectar` para reconectarse.")
	ce.User.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: WANotConnected})
}

var cmdPing = &commands.FullHandler{
	Func: wrapCommand(fnPing),
	Name: "ping",
	Help: commands.HelpMeta{
		Section:     HelpSectionConnectionManagement,
		Description: "Probar su conexión con WhatsApp.",
	},
}

func fnPing(ce *WrappedCommandEvent) {
	if ce.User.Session == nil {
		if ce.User.Client != nil {
			ce.Reply("Conectado a WhatsApp, pero sin iniciar sesión.")
		} else {
			ce.Reply("No tienes sesión iniciada con WhatsApp.")
		}
	} else if ce.User.Client == nil || !ce.User.Client.IsConnected() {
		ce.Reply("Tienes sesión iniciada como +%s (dispositivo #%d), pero no tienes una conexión con WhatsApp.", ce.User.JID.User, ce.User.JID.Device)
	} else {
		ce.Reply("Tienes sesión iniciada como +%s (dispositivo #%d), y la conexión a WhatsApp es OK (seguro)", ce.User.JID.User, ce.User.JID.Device)
		if !ce.User.PhoneRecentlySeen(false) {
			ce.Reply("El teléfono no se ha visto en %s", formatDisconnectTime(time.Now().Sub(ce.User.PhoneLastSeen)))
		}
	}
}

func canDeletePortal(portal *Portal, userID id.UserID) bool {
	if len(portal.MXID) == 0 {
		return false
	}

	members, err := portal.MainIntent().JoinedMembers(portal.MXID)
	if err != nil {
		portal.log.Errorfln("Failed to get joined members to check if portal can be deleted by %s: %v", userID, err)
		return false
	}
	for otherUser := range members.Joined {
		_, isPuppet := portal.bridge.ParsePuppetMXID(otherUser)
		if isPuppet || otherUser == portal.bridge.Bot.UserID || otherUser == userID {
			continue
		}
		user := portal.bridge.GetUserByMXID(otherUser)
		if user != nil && user.Session != nil {
			return false
		}
	}
	return true
}

var cmdDeletePortal = &commands.FullHandler{
	Func: wrapCommand(fnDeletePortal),
	Name: "eliminar-portal",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Elimina el portal corriente. Si el portal es utilizado por otras personas, está limitado a sólo administradores.",
	},
	RequiresPortal: true,
}

func fnDeletePortal(ce *WrappedCommandEvent) {
	if !ce.User.Admin && !canDeletePortal(ce.Portal, ce.User.MXID) {
		ce.Reply("Solamente administradores del puente pueden eliminar portales con otros usuarios Matrix")
		return
	}

	ce.Portal.log.Infoln(ce.User.MXID, "requested deletion of portal.")
	ce.Portal.Delete()
	ce.Portal.Cleanup(false)
}

var cmdDeleteAllPortals = &commands.FullHandler{
	Func: wrapCommand(fnDeleteAllPortals),
	Name: "eliminar-todos-los-portales",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Elimina todos los portales.",
	},
}

func fnDeleteAllPortals(ce *WrappedCommandEvent) {
	portals := ce.Bridge.GetAllPortals()
	var portalsToDelete []*Portal

	if ce.User.Admin {
		portalsToDelete = portals
	} else {
		portalsToDelete = portals[:0]
		for _, portal := range portals {
			if canDeletePortal(portal, ce.User.MXID) {
				portalsToDelete = append(portalsToDelete, portal)
			}
		}
	}
	if len(portalsToDelete) == 0 {
		ce.Reply("No se hallaron portales para eliminar")
		return
	}

	leave := func(portal *Portal) {
		if len(portal.MXID) > 0 {
			_, _ = portal.MainIntent().KickUser(portal.MXID, &mautrix.ReqKickUser{
				Reason: "Eliminando portal",
				UserID: ce.User.MXID,
			})
		}
	}
	customPuppet := ce.Bridge.GetPuppetByCustomMXID(ce.User.MXID)
	if customPuppet != nil && customPuppet.CustomIntent() != nil {
		intent := customPuppet.CustomIntent()
		leave = func(portal *Portal) {
			if len(portal.MXID) > 0 {
				_, _ = intent.LeaveRoom(portal.MXID)
				_, _ = intent.ForgetRoom(portal.MXID)
			}
		}
	}
	ce.Reply("Se encontraron %d portales, eliminando...", len(portalsToDelete))
	for _, portal := range portalsToDelete {
		portal.Delete()
		leave(portal)
	}
	ce.Reply("Eliminando la información de los portales completado. Ahora limpiando en el fondo las salas de los portales.")

	go func() {
		for _, portal := range portalsToDelete {
			portal.Cleanup(false)
		}
		ce.Reply("Limpiando en el fondo las salas de los portales completado.")
	}()
}

func matchesQuery(str string, query string) bool {
	if query == "" {
		return true
	}
	return strings.Contains(strings.ToLower(str), query)
}

func formatContacts(bridge *WABridge, input map[types.JID]types.ContactInfo, query string) (result []string) {
	hasQuery := len(query) > 0
	for jid, contact := range input {
		if len(contact.FullName) == 0 {
			continue
		}
		puppet := bridge.GetPuppetByJID(jid)
		pushName := contact.PushName
		if len(pushName) == 0 {
			pushName = contact.FullName
		}

		if !hasQuery || matchesQuery(pushName, query) || matchesQuery(contact.FullName, query) || matchesQuery(jid.User, query) {
			result = append(result, fmt.Sprintf("* %s / [%s](https://matrix.to/#/%s) - `+%s`", contact.FullName, pushName, puppet.MXID, jid.User))
		}
	}
	sort.Sort(sort.StringSlice(result))
	return
}

func formatGroups(input []*types.GroupInfo, query string) (result []string) {
	hasQuery := len(query) > 0
	for _, group := range input {
		if !hasQuery || matchesQuery(group.GroupName.Name, query) || matchesQuery(group.JID.User, query) {
			result = append(result, fmt.Sprintf("* %s - `%s`", group.GroupName.Name, group.JID.User))
		}
	}
	sort.Sort(sort.StringSlice(result))
	return
}

var cmdList = &commands.FullHandler{
	Func: wrapCommand(fnList),
	Name: "list",
	Help: commands.HelpMeta{
		Section:     HelpSectionMiscellaneous,
		Description: "Get a list of all contacts and groups.",
		Args:        "<`contacts`|`groups`> [_page_] [_items per page_]",
	},
	RequiresLogin: true,
}

func fnList(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Uso:** `listar <contactos|grupos> [página] [artículos por página]`")
		return
	}
	mode := strings.ToLower(ce.Args[0])
	if mode[0] != 'g' && mode[0] != 'c' {
		ce.Reply("**Uso:** `listar <contactos|grupos> [página] [artículos por página]`")
		return
	}
	var err error
	page := 1
	max := 100
	if len(ce.Args) > 1 {
		page, err = strconv.Atoi(ce.Args[1])
		if err != nil || page <= 0 {
			ce.Reply("\"%s\" no es un número válido de página", ce.Args[1])
			return
		}
	}
	if len(ce.Args) > 2 {
		max, err = strconv.Atoi(ce.Args[2])
		if err != nil || max <= 0 {
			ce.Reply("\"%s\" no es un número válido de artículos por página", ce.Args[2])
			return
		} else if max > 400 {
			ce.Reply("Advertencia: un número alto de artículos por página puede causar un fallo en recibir una respuesta")
		}
	}

	contacts := mode[0] == 'c'
	typeName := "grupos"
	var result []string
	if contacts {
		typeName = "contactos"
		contactList, err := ce.User.Client.Store.Contacts.GetAllContacts()
		if err != nil {
			ce.Reply("No se pudo conseguir los contactos: %s", err)
			return
		}
		result = formatContacts(ce.User.bridge, contactList, "")
	} else {
		groupList, err := ce.User.Client.GetJoinedGroups()
		if err != nil {
			ce.Reply("No se pudo conseguir los grupos: %s", err)
			return
		}
		result = formatGroups(groupList, "")
	}

	if len(result) == 0 {
		ce.Reply("No se hallaron %s", strings.ToLower(typeName))
		return
	}
	pages := int(math.Ceil(float64(len(result)) / float64(max)))
	if (page-1)*max >= len(result) {
		if pages == 1 {
			ce.Reply("Solamente hay 1 página de %s", strings.ToLower(typeName))
		} else {
			ce.Reply("Hay %d páginas de %s", pages, strings.ToLower(typeName))
		}
		return
	}
	lastIndex := page * max
	if lastIndex > len(result) {
		lastIndex = len(result)
	}
	result = result[(page-1)*max : lastIndex]
	ce.Reply("### %s (página %d de %d)\n\n%s", typeName, page, pages, strings.Join(result, "\n"))
}

var cmdSearch = &commands.FullHandler{
	Func: wrapCommand(fnSearch),
	Name: "buscar",
	Help: commands.HelpMeta{
		Section:     HelpSectionMiscellaneous,
		Description: "Buscar contactos o grupos.",
		Args:        "<_busqueda_>",
	},
	RequiresLogin: true,
}

func fnSearch(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Uso:** `buscar <busqueda>`")
		return
	}

	contactList, err := ce.User.Client.Store.Contacts.GetAllContacts()
	if err != nil {
		ce.Reply("No se pudieron conseguir los contactos: %s", err)
		return
	}
	groupList, err := ce.User.Client.GetJoinedGroups()
	if err != nil {
		ce.Reply("No se pudieron conseguir los grupos: %s", err)
		return
	}

	query := strings.ToLower(strings.TrimSpace(strings.Join(ce.Args, " ")))
	formattedContacts := strings.Join(formatContacts(ce.User.bridge, contactList, query), "\n")
	formattedGroups := strings.Join(formatGroups(groupList, query), "\n")

	result := make([]string, 0, 2)
	if len(formattedContacts) > 0 {
		result = append(result, "### Contactos\n\n"+formattedContacts)
	}
	if len(formattedGroups) > 0 {
		result = append(result, "### Groupos\n\n"+formattedGroups)
	}

	if len(result) == 0 {
		ce.Reply("No se hallaron contactos ni grupos")
		return
	}

	ce.Reply(strings.Join(result, "\n\n"))
}

var cmdOpen = &commands.FullHandler{
	Func: wrapCommand(fnOpen),
	Name: "abrir",
	Help: commands.HelpMeta{
		Section:     HelpSectionCreatingPortals,
		Description: "Abrir un portal de grupo.",
		Args:        "<_JID de grupo_>",
	},
	RequiresLogin: true,
}

func fnOpen(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Uso:** `abrir <JID de grupo>`")
		return
	}

	var jid types.JID
	if strings.ContainsRune(ce.Args[0], '@') {
		jid, _ = types.ParseJID(ce.Args[0])
	} else {
		jid = types.NewJID(ce.Args[0], types.GroupServer)
	}
	if (jid.Server != types.GroupServer && jid.Server != types.NewsletterServer) || (!strings.ContainsRune(jid.User, '-') && len(jid.User) < 15) {
		ce.Reply("Eso no se mira como un JID de grupo")
		return
	}

	var err error
	var groupInfo *types.GroupInfo
	var newsletterMetadata *types.NewsletterMetadata
	switch jid.Server {
	case types.GroupServer:
		groupInfo, err = ce.User.Client.GetGroupInfo(jid)
		if err != nil {
			ce.Reply("No se pudo conseguir la información del grupo: %v", err)
			return
		}
		jid = groupInfo.JID
	case types.NewsletterServer:
		newsletterMetadata, err = ce.User.Client.GetNewsletterInfo(jid)
		if err != nil {
			ce.Reply("No se pudo conseguir la información del canal: %v", err)
			return
		}
		jid = newsletterMetadata.ID
	}
	ce.Log.Debugln("Importing", jid, "for", ce.User.MXID)
	portal := ce.User.GetPortalByJID(jid)
	if len(portal.MXID) > 0 {
		portal.UpdateMatrixRoom(ce.User, groupInfo, newsletterMetadata)
		ce.Reply("Sala de portal sincronizada.")
	} else {
		err = portal.CreateMatrixRoom(ce.User, groupInfo, newsletterMetadata, true, true)
		if err != nil {
			ce.Reply("No se pudo crear la sala: %v", err)
		} else {
			ce.Reply("Sala de portal creada.")
		}
	}
}

var cmdPM = &commands.FullHandler{
	Func: wrapCommand(fnPM),
	Name: "pm",
	Help: commands.HelpMeta{
		Section:     HelpSectionCreatingPortals,
		Description: "Abrir un chat privado con el número indicado.",
		Args:        "<_número de teléfono internacional_>",
	},
	RequiresLogin: true,
}

func fnPM(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Uso:** `pm <número de teléfono internacional>`")
		return
	}

	user := ce.User

	number := strings.Join(ce.Args, "")
	resp, err := ce.User.Client.IsOnWhatsApp([]string{number})
	if err != nil {
		ce.Reply("No se pudo revisar si el usuario está en WhatsApp: %v", err)
		return
	} else if len(resp) == 0 {
		ce.Reply("No se recibió una respuesta al revisar si el usuario está en WhatsApp")
		return
	}
	targetUser := resp[0]
	if !targetUser.IsIn {
		ce.Reply("El servidor dice que +%s no está en WhatsApp", targetUser.JID.User)
		return
	}

	portal, puppet, justCreated, err := user.StartPM(targetUser.JID, "manual PM command")
	if err != nil {
		ce.Reply("Ocurrió un error al crear la sala de portal: %v", err)
	} else if !justCreated {
		ce.Reply("Ya tienes un portal de chat privado con +%s en [%s](https://matrix.to/#/%s)", puppet.JID.User, puppet.Displayname, portal.MXID)
	} else {
		ce.Reply("Sala de portal creado con +%s y has sido invitado.", puppet.JID.User)
	}
}

var cmdSync = &commands.FullHandler{
	Func: wrapCommand(fnSync),
	Name: "sincronizar",
	Help: commands.HelpMeta{
		Section:     HelpSectionMiscellaneous,
		Description: "Sincronizar datos de WhatsApp.",
		Args:        "<estado/contactos/grupos/espacio> [--avatars-de-contacto] [--crear-portales]",
	},
	RequiresLogin: true,
}

func fnSync(ce *WrappedCommandEvent) {
	args := strings.ToLower(strings.Join(ce.Args, " "))
	contacts := strings.Contains(args, "contacts")
	appState := strings.Contains(args, "appstate")
	space := strings.Contains(args, "space")
	groups := strings.Contains(args, "groups") || space
	if !contacts && !appState && !space && !groups {
		ce.Reply("**Uso:** `sincronizar <estado/contactos/grupos/espacio> [--avatars-de-contacto] [--crear-portales]`")
		return
	}
	createPortals := strings.Contains(args, "--crear-portales")
	contactAvatars := strings.Contains(args, "--avatars-de-contacto")
	if contactAvatars && (!contacts || appState) {
		ce.Reply("`--avatars-de-contacto` sólo puede ser usado con `sincronizar contactos`")
		return
	}
	if createPortals && !groups {
		ce.Reply("`--create-portals` can only be used with `sync groups`")
		return
	}

	if appState {
		for _, name := range appstate.AllPatchNames {
			err := ce.User.Client.FetchAppState(name, true, false)
			if errors.Is(err, appstate.ErrKeyNotFound) {
				ce.Reply("Error de llave no hallada al sincronizar estado de aplicación %s: %v\n\nLas peticiones de llaves son enviadas automáticamente, y la sincronización debe ocurrir en el fondo luego de que su teléfono responda.", name, err)
				return
			} else if err != nil {
				ce.Reply("Error sincronizando el estado de aplicación %s: %v", name, err)
			} else if name == appstate.WAPatchCriticalUnblockLow {
				ce.Reply("Estado de aplicación %s sincronizado, sincronización de contactos corriendo en el fondo", name)
			} else {
				ce.Reply("Estado de aplicación %s sincronizado", name)
			}
		}
	} else if contacts {
		err := ce.User.ResyncContacts(contactAvatars)
		if err != nil {
			ce.Reply("Error resincronizando contactos: %v", err)
		} else {
			ce.Reply("Contactos resincronizados")
		}
	}
	if space {
		if !ce.Bridge.Config.Bridge.PersonalFilteringSpaces {
			ce.Reply("Espacios personales filtrados no están habilitados en esta instancia del puente")
			return
		}
		keys := ce.Bridge.DB.Portal.FindPrivateChatsNotInSpace(ce.User.JID)
		count := 0
		for _, key := range keys {
			portal := ce.Bridge.GetPortalByJID(key)
			portal.addToPersonalSpace(ce.User)
			count++
		}
		plural := "s"
		if count == 1 {
			plural = ""
		}
		ce.Reply("%d sala%s agregada%s al espacio", count, plural, plural)
	}
	if groups {
		err := ce.User.ResyncGroups(createPortals)
		if err != nil {
			ce.Reply("Error resincronizando grupos: %v", err)
		} else {
			ce.Reply("Grupos resincronizados")
		}
	}
}

var cmdDisappearingTimer = &commands.FullHandler{
	Func:    wrapCommand(fnDisappearingTimer),
	Name:    "disappearing-timer",
	Aliases: []string{"disappear-timer"},
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Set future messages in the room to disappear after the given time.",
		Args:        "<off/1d/7d/90d>",
	},
	RequiresLogin:  true,
	RequiresPortal: true,
}

func fnDisappearingTimer(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Usage:** `disappearing-timer <off/1d/7d/90d>`")
		return
	}
	duration, ok := whatsmeow.ParseDisappearingTimerString(ce.Args[0])
	if !ok {
		ce.Reply("Invalid timer '%s'", ce.Args[0])
		return
	}
	prevExpirationTime := ce.Portal.ExpirationTime
	ce.Portal.ExpirationTime = uint32(duration.Seconds())
	err := ce.User.Client.SetDisappearingTimer(ce.Portal.Key.JID, duration)
	if err != nil {
		ce.Reply("Failed to set disappearing timer: %v", err)
		ce.Portal.ExpirationTime = prevExpirationTime
		return
	}
	ce.Portal.Update(nil)
	ce.React("✅")
}
