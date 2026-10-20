# RAC user service

Servicio Go/Gin de usuarios, perfiles y publicacion de compas. Los esquemas SQL
versionados y la documentacion transversal viven en rac-infra-docker.

## Fotos de perfil

PROFILE_PHOTO_STORAGE selecciona local (por defecto) o s3. Un valor desconocido
o una configuracion S3 incompleta impide arrancar; no hay fallback automatico.

- Local: PROFILE_PHOTO_DIR, por defecto /var/lib/rac/photos.
- S3: PROFILE_S3_ENDPOINT, PROFILE_S3_REGION, PROFILE_S3_BUCKET,
  PROFILE_S3_ACCESS_KEY y PROFILE_S3_SECRET_KEY. SDK AWS Go v2 con firma SigV4,
  addressing path-style, timeout HTTP de 8 s y dos intentos maximos.
- El backend recibe y normaliza JPEG/PNG, aplica OIDC/publicacion y sirve los bytes.
  Flutter nunca recibe credenciales ni URLs directas al bucket privado.
- /ready comprueba Postgres y el bucket configurado; /health comprueba el proceso.
  Un objeto inexistente devuelve 404; almacenamiento inaccesible devuelve 503.
- La identidad de ejecucion necesita ListBucket (HeadBucket), GetObject,
  PutObject y DeleteObject exclusivamente en su bucket. No crea buckets ni IAM.

El comando cmd/migrate-photos requiere S3, DATABASE_URL y PROFILE_PHOTO_DIR.
Copia solo archivos referenciados, bloquea filas, verifica bytes y conserva el
origen y las referencias. Repetible; rechaza conflictos y archivos faltantes.
Detener el servicio de usuarios durante la migracion y activar S3 solo si termina
correctamente. Operacion reproducible: docs/almacenamiento-rustfs.md en infra.

## Pruebas

`go vet ./...` y `go test -race ./...`. Los tests con base real requieren
RAC_ONBOARDING_TEST_DATABASE_URL apuntando a una base desechable migrada.
RAC_PHOTO_TEST_S3_ENDPOINT junto con PROFILE_S3_* habilita la variante RustFS.
El script infra/scripts/test_photo_storage.py prepara la base, ejecuta las pruebas
y limpia los datos de prueba. Nunca usar una base de usuarios reales para tests.
