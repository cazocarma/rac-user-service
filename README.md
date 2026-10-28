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

## Resenas verificadas y coordinacion de respaldos

POST/GET /api/user/bookings/:id/review requieren OIDC y propiedad/participacion.
POST exige cliente contratante, estado finalizada y horario ya terminado. Una
resena por reserva; repetir el mismo contenido devuelve la existente, y cambiarla
se rechaza. GET /api/user/compas/:id/reviews pagina publicamente sin datos del autor.
La media y cantidad del compa se calculan de reserva_resena; requieren migracion V008.

Guardar/eliminar fotos obtiene el advisory lock transaccional compartido
(726224,1). El agente de respaldo obtiene el exclusivo antes de exportar snapshot
y copiar las fotos referenciadas. Mantener esta coordinacion al agregar otras
rutas de escritura/limpieza de fotos. No copiar directamente volumenes en caliente.


## Ingreso editorial interno (preparado, apagado)

El listener separado de puerto 8083 acepta comandos del cliente staff para
borrador, revisión y publicación de documentos. No se registra en el router
público ni se agrega un puerto de host al stack. Rutas:

- `POST /internal/documents/drafts`: id/evento/hash, tipo/versión/idioma, texto
  exacto y material_change explícito.
- `POST /internal/documents/reviews`: id/evento/hash y decisión approved/rejected;
  no permite al autor revisar su propio borrador.
- `POST /internal/documents/publications`: id/evento/hash; requiere la revisión
  aprobada exacta y no activa por sí solo el registro de obligaciones.
- `GET /internal/documents/{id}`: texto/hash y metadata de la revisión exacta,
  incluido un borrador todavía no público, solo con permiso legal.
- `GET /ready`: estado de la conexión/configuración de auditoría del principal
  editorial, sin datos de documentos, identidades o cadenas.

La firma/issuer/audiencia `rac-user-documents`, azp rac-staff, rol de cliente
legal y MFA reciente se verifican mediante rac-platform/staff. Actor se deriva
del contexto verificado y política de la configuración; el JSON rechaza campos
que pretendan imponerlos, propiedades repetidas (también variantes de mayúsculas),
valores adicionales, texto no UTF-8 y cuerpos mayores de 1 MiB. Texto de borrador:
máximo 131072 bytes UTF-8, no blanco ni NUL, con SHA256 exacto. Cada comando
comparte transacción con auditoría y comprueba otra vez permiso/vencimiento antes
de commit. Esperas se acotan a cinco segundos y al vencimiento del token/MFA;
un reintento idéntico conserva el primer resultado. No se repite automáticamente.

Configuración: DOCUMENT_EDITORIAL_ENABLED=false por defecto. Para prepararlo se
requieren DOCUMENT_EDITORIAL_DATABASE_URL (sin fallback al usuario normal),
DOCUMENT_EDITORIAL_POLICY_VERSION (referencia UUID no nula autorizada por el
operador), OIDC_ISSUER y OIDC_JWKS_URL. No se toma política del cuerpo ni se
certifica su aprobación jurídica por ser un UUID válido. Un valor ambiguo del
flag o credenciales amplias detiene la activación. La conexión dedicada no puede
ser superusuario/creador de roles, miembro de otros roles ni tener lectura/DML
sobre tablas de negocio; tampoco ejecución directa de audit.append, activate o
el helper de eventos. Se permite metadata de catálogo/extensiones. Su perfil de
provisión consiste en USAGE de los esquemas necesarios y EXECUTE de las diez
funciones comprobadas por internal/editorial.requiredSignatures, sin grants de tablas.
El escritor/chain de auditoría se provisiona por el operador y se verifica al
iniciar; su pérdida vuelve readiness a 503 y revierte cualquier escritura.

La migración no crea ese login ni lo asigna a los roles actuales, y este
incremento no agrega el flag a overlays. El cliente staff continúa deshabilitado
hasta el enrolamiento/activación aprobados; preparar la audiencia no concede roles.
Faltan la provisión operativa, la consola web de revisión y el ensayo conectado
del flujo completo. El proxy y la activación atómica ya tienen implementación local. No hay semillas jurídicas ni cambios en DEV persistente.

### Cuestionario y activación conjunta (V036)

El mismo listener ofrece POST /internal/assessments/drafts, /reviews y
/publications y GET /internal/assessments/{id}. El servidor valida cinco
compromisos y tres preguntas y calcula el hash del JSON canónico; el cliente
no puede imponer el hash del borrador ni metadatos de aprobación. La lectura
editorial contiene la clave privada; el contrato público sigue excluyéndola.
El catálogo tipado impide confundir un cuestionario con un documento incluso
si coinciden sus UUID y hashes.

POST /internal/documents/activations recibe event_id, expected_version, locale,
cinco referencias document_id/sha256, una referencia definition_id/sha256 y
summary. Exige publicaciones revisadas por otra persona y confirma registro,
vínculo de cuestionario y auditoría en una sola transacción. La versión esperada
impide ganar dos activaciones concurrentes. Repetir un evento devuelve su versión
histórica sin retroceder el registro; una activación antigua hecha por SQL no se
adopta retroactivamente como una activación editorial atómica.
