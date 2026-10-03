package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != sha256.Size*2 {
		return false
	}
	providedSignature, err := hex.DecodeString(signature)
	if err != nil || len(providedSignature) != sha256.Size {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil {
		return false
	}
	expectedSignature, err := hex.DecodeString(signDownload(signingKey, fileID, expires))
	if expires <= now.Unix() || subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(providedSignature)) != 1 {
		return false
	}
	return true
}

func signDownload(signingKey [32]byte, fileID int64, expires int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	signature := hex.EncodeToString(mac.Sum(nil))
	return signature
}
