package contentsignals

// ProposedLexicon is the prompt's drugs seed, pending T&S curation (D13).
// sexual_services and minors stay empty until specialised review: they are
// reported as unevaluated, never invented here. Weapons, violence and
// off-platform payment have no curated seed yet either.
func ProposedLexicon() Lexicon {
	sale := []string{"vendo", "venta", "precio", "x gramo", "por gramo", "gramo", "gramos", "gr", "delivery", "envio", "tengo", "dispongo", "lucas", "pido"}
	return Lexicon{Version: "proposed-2026-11", Status: "proposed", Rules: []Rule{
		{ID: "drugs.slang_strong", Category: CategoryDrugs, Weight: 0.7, Terms: []string{
			"merca", "falopa", "perico", "tusi", "tussi", "2cb", "keta", "ketamina", "extasis", "mdma",
			"cripy", "kripy", "paco", "pasta base",
		}},
		{ID: "drugs.cannabis", Category: CategoryDrugs, Weight: 0.5, Terms: []string{"mota", "weed", "porro"}},
		{ID: "drugs.cocaine_context", Category: CategoryDrugs, Weight: 0.6, Terms: []string{"coca"},
			RequiresAny: sale, ExcludeIfAny: []string{"cola", "coca cola", "hoja de coca", "te de coca", "mate de coca"}},
		{ID: "drugs.pills_context", Category: CategoryDrugs, Weight: 0.5, Terms: []string{"pastis", "pastillas", "md"},
			RequiresAny:  []string{"vendo", "venta", "precio", "delivery", "fiesta", "carrete", "lucas", "dispongo"},
			ExcludeIfAny: []string{"receta", "medico", "farmacia", "doctor"}},
		{ID: "drugs.lsd", Category: CategoryDrugs, Weight: 0.7, Terms: []string{"lsd"}},
		{ID: "drugs.lsd_context", Category: CategoryDrugs, Weight: 0.5, Terms: []string{"acido", "carton"},
			RequiresAny:  []string{"lsd", "viaje", "vendo", "venta", "gotas", "microdosis"},
			ExcludeIfAny: []string{"reciclaje", "caja de carton", "acido folico", "acido citrico", "acido hialuronico"}},
		{ID: "drugs.pipe_context", Category: CategoryDrugs, Weight: 0.4, Terms: []string{"cano"},
			RequiresAny: []string{"fumar", "mota", "weed", "prender", "porro"}},
		{ID: "drugs.good_stuff", Category: CategoryDrugs, Weight: 0.4, Terms: []string{"la buena"},
			RequiresAny: []string{"vendo", "tengo", "gramo", "lucas", "delivery"}},
		{ID: "drugs.plug", Category: CategoryDrugs, Weight: 0.5, Terms: []string{"plug"},
			RequiresAny: []string{"vendo", "delivery", "tengo", "merca", "weed", "pedidos"}},
		{ID: "drugs.per_gram", Category: CategoryDrugs, Weight: 0.4, Terms: []string{"x gramo", "por g", "por gramo"}},
		{ID: "drugs.mushrooms", Category: CategoryDrugs, Weight: 0.5, Terms: []string{"hongos"},
			RequiresAny:  []string{"magicos", "viaje", "psilocibina", "microdosis"},
			ExcludeIfAny: []string{"receta", "cocina", "risotto", "ensalada", "champinon", "champinones", "salteados"}},
	}}
}
