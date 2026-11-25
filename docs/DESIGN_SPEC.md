# TULPAR UI & Design Specification

TULPAR uses an identical, ultra-minimalist Turkish visual language on Android and Windows (plus a clean CLI/systemd workflow on Linux).

## 1. Main Screen
- **Background**: Pure `#000000` across the entire viewport (including system status/navigation bars on Android and DWM dark titlebar on Windows).
- **Center Element**: Single circular toggle button (`diameter = clamp(min(w,h)*0.42, 160, 220)` dp/pt/px).
- **Top-Right Corner**: Small minimalist settings gear icon (`#7A7A7A`, accessible label `Ayarlar`) opening the Settings screen.
- **First-Launch Security Warning**: Shown once on first open on `#000000` with exact Turkish text:
  > `GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir.`
- **Prohibited Elements**: No ads, no splash screens, no decorative animations, no cluttered menus or logs.

## 2. Main Button State Palette
| State | Fill | Stroke | Glyph | Accessibility Label (TR) |
|---|---|---|---|---|
| **Passive** (`Inactive`) | `#000000` | `#444444` (2px) | `#7A7A7A` | `TULPAR: Pasif. Korumayı açmak için dokunun.` |
| **Transition** (`Activating` / `Deactivating`) | `#000000` | `#999999` (2px) | `#CCCCCC` | `TULPAR: İşlem yapılıyor.` |
| **Active** (`Active`) | `#FFFFFF` | `#FFFFFF` | `#000000` | `TULPAR: Aktif. Korumayı kapatmak için dokunun.` |
| **Error** (`Error`) | `#000000` | `#C93B3B` (2px) | `#C93B3B` | `TULPAR: Hata veya izin reddedildi. Tekrar deneyin.` |

## 3. Settings Screen (`Ayarlar`)
- Pure `#000000` background, top-left back arrow (`←`) + `Ayarlar`.
- **Single Non-Wrapping Horizontal Row of 7 Module Icons** (horizontally scrollable on narrow mobile screens, NEVER wrapping onto a second line):
  1. `Akıllı Koruma`
  2. `DNS Koruması`
  3. `Reklam ve Takip Engelleme`
  4. `Gelişmiş Sansür Aşma`
  5. `Bağlantı Güvenliği`
  6. `Performans`
  7. `Güncellemeler`
- **Real Health Color Rules (Zero Fake Success)**:
  - **Green (`#2ECC71`)**: Verified working via real health checks.
  - **Red (`#E74C3C`)**: Error, permission denied, missing driver, or failed check.
  - **Gray (`#6E6E6E`)**: Passive (protection off), not yet checked, or temporary Captive Portal login allowance.
- **Error & Tap Readout**:
  - When 1 or more modules are Red, display full module names + short Turkish error messages in red (`#E74C3C`) directly beneath the icon row.
  - When no modules are in error, show zero unnecessary error text.
  - Tapping any icon reveals that module's full Turkish name and real current status.
- **Manual Update Check Button**: `Güncellemeleri Kontrol Et` directly below status icons (runs ONLY on explicit user tap; checks ONLY official GitHub Releases; never runs in background; never uses an invented repo URL).
- **Security Warning**: Prominent minimalist warning box directly below the update button with the exact Turkish text above.
