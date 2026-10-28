package httpapi

import (
	"github.com/cazocarma/rac-user-service/internal/strictjson"
	"io"
)

func decodeUniqueJSON(reader io.Reader, target any) error { return strictjson.Decode(reader, target) }
