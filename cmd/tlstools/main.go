package main

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jsandas/tlstools/pkg/controllers"
)

func main() {
	router := chi.NewRouter()

	router.Use(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Logger,
		middleware.Recoverer,
		middleware.Timeout(60*time.Second),
	)

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tlstools service"))
	})

	router.Route("/api/v1", func(r chi.Router) {
		r.Mount("/scan", controllers.ScanRoutes())
		r.Mount("/parse", controllers.ParserRoutes())
	})

	log.Fatal(http.ListenAndServe(":8080", router))
}
