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
	"fmt"
	"net/http"

	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/id"
)

const (
	WALoggedOut        status.BridgeStateErrorCode = "wa-logged-out"
	WAMainDeviceGone   status.BridgeStateErrorCode = "wa-main-device-gone"
	WAUnknownLogout    status.BridgeStateErrorCode = "wa-unknown-logout"
	WANotConnected     status.BridgeStateErrorCode = "wa-not-connected"
	WAConnecting       status.BridgeStateErrorCode = "wa-connecting"
	WAKeepaliveTimeout status.BridgeStateErrorCode = "wa-keepalive-timeout"
	WAPhoneOffline     status.BridgeStateErrorCode = "wa-phone-offline"
	WAConnectionFailed status.BridgeStateErrorCode = "wa-connection-failed"
	WADisconnected     status.BridgeStateErrorCode = "wa-transient-disconnect"
)

func init() {
	status.BridgeStateHumanErrors.Update(status.BridgeStateErrorMap{
		WALoggedOut:        "La sesión fue cerrada desde otro dispositivo. Vuelva a iniciar sesión para continuar utilizando este puente.",
		WAMainDeviceGone:   "La sesión fue cerrada desde tu teléfono. Vuelva a iniciar sesión para continuar utilizando este puente.",
		WAUnknownLogout:    "La sesión fue cerrada por un motivo desconocido. Vuelva a iniciar sesión para continuar utilizando este puente.",
		WANotConnected:     "No estás conectado a WhatsApp",
		WAConnecting:       "Reconectando a WhatsApp...",
		WAKeepaliveTimeout: "Los servidores de WhatsApp no están respondiendo. El puente intentará reconectarse.",
		WAPhoneOffline:     "Su teléfono no se ha visto en más de 12 días. El puente está actualmente conectado, pero se desconectará si no abres la aplicación pronto.",
		WAConnectionFailed: "Conectarse a los servidores de WhatsApp falló.",
		WADisconnected:     "Desconectado de WhatsApp. Intentando reconectar.",
	})
}

func (user *User) GetRemoteID() string {
	if user == nil || user.JID.IsEmpty() {
		return ""
	}
	return user.JID.User
}

func (user *User) GetRemoteName() string {
	if user == nil || user.JID.IsEmpty() {
		return ""
	}
	return fmt.Sprintf("+%s", user.JID.User)
}

func (prov *ProvisioningAPI) BridgeStatePing(w http.ResponseWriter, r *http.Request) {
	if !prov.bridge.AS.CheckServerToken(w, r) {
		return
	}
	userID := r.URL.Query().Get("user_id")
	user := prov.bridge.GetUserByMXID(id.UserID(userID))
	var global status.BridgeState
	global.StateEvent = status.StateRunning
	var remote status.BridgeState
	if user.IsConnected() {
		if user.Client.IsLoggedIn() {
			remote.StateEvent = status.StateConnected
		} else if user.Session != nil {
			remote.StateEvent = status.StateConnecting
			remote.Error = WAConnecting
		} // else: unconfigured
	} else if user.Session != nil {
		remote.StateEvent = status.StateBadCredentials
		remote.Error = WANotConnected
	} // else: unconfigured
	global = global.Fill(nil)
	resp := status.GlobalBridgeState{
		BridgeState:  global,
		RemoteStates: map[string]status.BridgeState{},
	}
	if len(remote.StateEvent) > 0 {
		remote = remote.Fill(user)
		resp.RemoteStates[remote.RemoteID] = remote
	}
	user.log.Debugfln("Responding bridge state in bridge status endpoint: %+v", resp)
	jsonResponse(w, http.StatusOK, &resp)
	if len(resp.RemoteStates) > 0 {
		user.BridgeState.SetPrev(remote)
	}
}
