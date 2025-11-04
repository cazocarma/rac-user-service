package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type CompaPerfil struct {
	ID                string   `json:"id"`
	UsuarioID         string   `json:"usuario_id"`
	Descripcion       string   `json:"descripcion"`
	TarifaHora        float64  `json:"tarifa_hora"`
	Habilidades       []string `json:"habilidades"`
	RatingPromedio    float64  `json:"rating_promedio"`
	FotoURL           string   `json:"foto_url"`
	DisponibilidadRaw string   `json:"disponibilidad_json"`
	// ubicacion omitida en DTO simple
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok", "service": "rac-user-service"}) })

	api := r.Group("/api/user")
	{
		api.GET("/compas", func(c *gin.Context) {
			// Filtros básicos (ejemplo)
			rows, err := db.Query(`
				SELECT id, usuario_id, descripcion, tarifa_hora, habilidades, rating_promedio, foto_url, disponibilidad_json
				FROM compa_perfil 
				LIMIT 50`)
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			var out []CompaPerfil
			for rows.Next() {
				var cp CompaPerfil
				err = rows.Scan(&cp.ID, &cp.UsuarioID, &cp.Descripcion, &cp.TarifaHora, &cp.Habilidades, &cp.RatingPromedio, &cp.FotoURL, &cp.DisponibilidadRaw)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
				out = append(out, cp)
			}
			c.JSON(http.StatusOK, out)
		})
	}

	addr := ":8080"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}
	log.Printf("user service listening on %s", addr)
	_ = r.Run(addr)
}
