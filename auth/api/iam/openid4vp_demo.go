/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package iam

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"net/http"
	"net/url"
	"strings"
)

func (r *Wrapper) handleOpenID4VPDemoLanding(echoCtx echo.Context) error {
	requestURL := *echoCtx.Request().URL
	requestURL.Host = echoCtx.Request().Host
	requestURL.Scheme = "http"
	verifierID := requestURL.String()
	verifierID, _ = strings.CutSuffix(verifierID, "/openid4vp_demo")

	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo.html", struct {
		VerifierID string
		WalletID   string
	}{
		VerifierID: verifierID,
		WalletID:   verifierID,
	}); err != nil {
		return err
	}
	return echoCtx.HTML(http.StatusOK, buf.String())
}

func (r *Wrapper) handleOpenID4VPDemoSendRequest(echoCtx echo.Context) error {
	verifierID := echoCtx.FormValue("verifier_id")
	if verifierID == "" {
		return errors.New("missing verifier_id")
	}
	verifierDID, err := did.ParseDID(echoCtx.Param("did"))
	if err != nil {
		return fmt.Errorf("invalid verifier DID: %w", err)
	}
	walletID := echoCtx.FormValue("wallet_id")
	if walletID == "" {
		return errors.New("missing wallet_id")
	}
	scope := echoCtx.FormValue("scope")
	if scope == "" {
		return errors.New("missing scope")
	}
	walletURL, _ := url.Parse(walletID)
	verifierURL, _ := url.Parse(verifierID)

	if echoCtx.Param("serverWallet") != "" {
		return r.sendPresentationRequest(
			echoCtx.Request().Context(), echoCtx.Response(), scope,
			*walletURL.JoinPath("openid4vp_completed"), *verifierURL, *walletURL,
		)
	} else {
		// Render QR code
		session := Session{
			Scope:  scope,
			OwnDID: *verifierDID,
		}
		sessionID := r.sessions.Create(session)
		redirectURL := *verifierURL.JoinPath("openid4vp_completed")
		redirectURL.RawQuery = url.Values{"session_id": []string{sessionID}}.Encode() // TODO: fix this
		requestObjectParams := r.createPresentationRequest(scope, redirectURL, *verifierURL)
		requestObjectParams["iss"] = verifierDID

		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signedRequestObject := jwt.New(jwt.SigningMethodES256)
		signedRequestObject.Claims = jwt.MapClaims(requestObjectParams)
		session.RequestObject, err = signedRequestObject.SignedString(privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign request object: %w", err)
		}
		r.sessions.Update(sessionID, session)

		qrCode := "openid://?" + url.Values{"request_uri": []string{verifierURL.JoinPath("openid4vp_demo", sessionID).String()}}.Encode()

		// Show QR code to scan using (mobile) wallet
		buf := new(bytes.Buffer)
		if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo_qrcode.html", struct {
			SessionID string
			QRCode    string
		}{
			SessionID: sessionID,
			QRCode:    qrCode,
		}); err != nil {
			return err
		}
		return echoCtx.HTML(http.StatusOK, buf.String())
	}
}

func (r *Wrapper) handleOpenID4VPDemoGetRequestURI(echoCtx echo.Context) error {
	sessionID := echoCtx.Param("sessionID")
	if sessionID == "" {
		return echoCtx.JSON(http.StatusBadRequest, "missing sessionID")
	}
	session := r.sessions.Get(sessionID)
	if session == nil {
		return echoCtx.JSON(http.StatusNotFound, "unknown session")
	}
	return echoCtx.Blob(http.StatusOK, "text/plain", []byte(session.RequestObject))
}

func (r *Wrapper) handleOpenID4VPDemoRequestWalletStatus(echoCtx echo.Context) error {
	sessionID := echoCtx.FormValue("sessionID")
	if sessionID == "" {
		return echoCtx.JSON(http.StatusBadRequest, "missing sessionID")
	}
	session := r.sessions.Get(sessionID)
	if session == nil {
		return echoCtx.JSON(http.StatusNotFound, "unknown session")
	}
	if session.Presentation == nil {
		// No VP yet, keep polling
		return echoCtx.NoContent(http.StatusNoContent)
	}
	return echoCtx.JSON(http.StatusOK, session.Presentation)
}
