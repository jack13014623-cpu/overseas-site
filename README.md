# 境外網頁代理

Flask 反向改寫代理，部署在 Render（美國 Oregon）。登入後把網址貼進首頁，
或直接開 `/p/https/網域/路徑`，所有對外連線由境外主機發出。

- 通行碼：環境變數 `PROXY_PASS`（未設則整站 503）
- Cookie 簽章：`PROXY_SECRET`
- 本機跑：`PROXY_PASS=test python3.12 app.py` → http://127.0.0.1:5055
- 限制：登入態網站、影片、重度 JS 網站不保證可用；WebSocket 不支援。
