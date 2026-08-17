# Auto Quest License API

ระบบ API และหน้า Admin สำหรับควบคุมสิทธิ์เข้าใช้งานแอปบนคอม โฟลเดอร์นี้แยกจากเว็บและแอปเดิมโดยสมบูรณ์

## สิ่งที่ทำงานแล้ว

- สร้าง Admin คนแรกด้วย Setup Token ที่แสดงใน Terminal
- เข้าสู่ระบบด้วย session cookie แบบ HttpOnly
- สร้าง License Key พร้อมวันหมดอายุและจำนวนเครื่อง
- เปิดใช้ ตรวจสอบ และยกเลิกการผูก License ผ่าน API
- ระงับ/เปิดใช้ License และล้างเครื่องจากหน้า Admin
- เก็บรหัสผ่าน, License Key และ session token เป็นค่าแฮช
- เก็บข้อมูล local ด้วย SQLite โดยไม่ต้องติดตั้งฐานข้อมูลเพิ่ม

## เริ่มใช้งานบนเครื่อง

ต้องใช้ Node.js 22.5 ขึ้นไป โปรเจกต์นี้ไม่ต้องติดตั้ง package เพิ่ม

```powershell
cd C:\Users\Administrator\Documents\auto-quest\api-server
npm start
```

Terminal จะแสดงข้อมูลประมาณนี้:

```text
Auto Quest License API: http://127.0.0.1:3211
Administrator setup is required.
Setup token: SETUP-xxxxxxxx
Open: http://127.0.0.1:3211/admin
```

เปิด `http://127.0.0.1:3211/admin` แล้วนำ Setup Token ไปสร้างบัญชี Admin ครั้งแรก หลังสร้างแล้ว Setup Token จะใช้สร้าง Admin เพิ่มไม่ได้

ข้อมูลและ secret ของเครื่องจะอยู่ใน `api-server/data/` และถูกตั้งค่าไม่ให้อัปโหลดขึ้น Git แล้ว ห้ามลบโฟลเดอร์นี้หากยังต้องการใช้ License เดิม

## API สำหรับตัวแอป

เปิดใช้งาน Key:

```http
POST /api/license/activate
Content-Type: application/json

{
  "licenseKey": "AQ-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "รหัสประจำ installation ความยาว 8-128 ตัวอักษร",
  "deviceName": "ชื่อคอมของผู้ใช้"
}
```

API จะคืน `accessToken` ซึ่งตัวแอปควรเก็บใน secure storage ของระบบปฏิบัติการ

ตรวจสอบ session:

```http
POST /api/license/verify
Authorization: Bearer ACCESS_TOKEN
Content-Type: application/json

{}
```

ยกเลิกการผูกเครื่อง:

```http
POST /api/license/deactivate
Authorization: Bearer ACCESS_TOKEN
Content-Type: application/json

{}
```

## ทดสอบ

```powershell
npm test
```

## ก่อนนำขึ้นเซิร์ฟเวอร์จริง

เวอร์ชันนี้ตั้งใจให้พัฒนาและทดสอบบนเครื่องก่อน ขั้น production ควรเปลี่ยน SQLite เป็น PostgreSQL, กำหนด `SESSION_SECRET` และ `LICENSE_PEPPER` ผ่าน secret manager, ตั้ง `NODE_ENV=production`, เปิดผ่าน HTTPS และตั้งค่า backup ฐานข้อมูล

ระบบ License นี้ไม่รับหรือเก็บ Discord user token การเชื่อม Discord ควรใช้ OAuth2/API ทางการแยกต่างหาก
