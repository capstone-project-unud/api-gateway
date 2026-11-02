# API gateway

Pintu masuk HTTP berbasis Go Fiber v3. **Tidak membutuhkan database.** Tidak menyimpan akun, kata sandi, profil, atau sesi. Login/logout/kata sandi diteruskan ke auth-service; pengguna/profil diteruskan ke user-service. Route `/internal/*` tidak dipublikasikan.

Salin `.env.example` menjadi `.env`, lalu `go run ./cmd/api`. Pemeriksaan: `go test ./...`, `go vet ./...`, `go build ./cmd/api`.

Frontend Nuxt menjadi BFF pada origin yang sama. Browser mengakses `/api/v1/*` di Nuxt, kemudian gateway pada jaringan internal. Gateway membatasi request, memeriksa Origin, menolak request lintas situs, dan hanya meneruskan header yang diperlukan. User-service tetap memeriksa otorisasi; melewati gateway tidak menghilangkan pemeriksaan sesi dan peran pada layanan bisnis.

`ALLOWED_ORIGIN` harus sama dengan URL frontend yang dipakai pengguna. Local default `http://localhost:3000`. Dengan `TRUST_BFF=true`, gateway menggunakan `X-Client-IP` yang ditulis ulang oleh Nuxt berdasarkan socket koneksinya. Konfigurasi ini hanya aman saat gateway dibatasi ke BFF/jaringan tepercaya, seperti Compose yang disediakan. Jangan mempercayai header tersebut pada gateway yang dipublikasikan langsung.

Batas default per IP dan per instance: gateway 180 request/menit, login 10 percobaan/menit. Untuk beberapa replika, gunakan penyimpanan rate limit bersama (misalnya Redis) dan konfigurasi proxy tepercaya sesuai deployment. Gateway bukan pengganti TLS terminator atau otorisasi layanan.

Mode pengembangan Docker menggunakan `Dockerfile.dev` dengan Air v1.67.4. Konfigurasi `.air.toml` memantau source Go dan berkas modul untuk kompilasi ulang otomatis. Mode ini diaktifkan melalui tambahan `infrastructure/compose.dev.yaml`; Dockerfile utama menjalankan binary hasil kompilasi.
