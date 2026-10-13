# חזרה חיה: שרת עצמאי + Quick Tunnel (שלב 2) - מוכן לביצוע, מותנה באישור

מטרה: להוכיח על ה-PC האמיתי את מסלול Efi - שרת עצמאי + מנהרת cloudflared יוצאת + supervisor +
קובץ state - כולל תרגיל rotation ופקודה חתומה מקצה-לקצה. בלי שינויי firewall/ראוטר (bind על
127.0.0.1 בלבד, cloudflared יוצא החוצה). בלי admin. מפתחות חזרה חד-פעמיים בלבד - לא מפתחות הייצור.

מה זה לא מוכיח: לא את שרת הייצור, לא את הזרימות של האפליקציה המותקנת, ולא מחליף עדיין את ה-worker.

## הודעה 1 - הורדת Node נייד
להוריד את קובץ ה-zip של Node ל-Windows (גרסה מדויקת + sha256 יצורפו בזמן האישור - יאומתו מול
nodejs.org באותו רגע) ולפרוס לתוך: %USERPROFILE%\gw-rehearsal\node
(אין התקנה, אין admin - פריסה בלבד.)

## הודעה 2 - הורדת הריפו
להוריד את ה-zip של הבראנץ':
https://codeload.github.com/avrahamyona/glass-widgets/zip/refs/heads/wip-0468-pairing-release
ולפרוס לתוך: %USERPROFILE%\gw-rehearsal\repo (כך ש-server\index.js יושב ישירות מתחת ל-repo).

## הודעה 3 - הגדרה (פיקסצ'ר win-rehearsal-setup.txt)
להוריד את הפיקסצ'ר שיצורף באישור, לשנות סיומת ל-.ps1 ולהריץ ב-PowerShell רגיל (לא admin).
הוא יוצר %USERPROFILE%\gw-rehearsal\data\config.json עם: token חד-פעמי, senderPub של זוג
מפתחות חזרה שאני מייצר ב-sandbox (המפתח הפרטי נשאר אצלי בלבד ומושמד אחרי החזרה),
port 47700, ו-roots לתיקיית scratch בלבד. הפיקסצ'ר מדפיס את כל מה שהוא כותב.

## הודעה 4 - הרצה (פיקסצ'ר win-rehearsal-run.txt)
להריץ ב-PowerShell רגיל. מריץ node server\index.js עם GW_SERVER_CONFIG + GW_TUNNEL=1.
צפוי: "server up on 127.0.0.1:47700" ואז "tunnel supervisor up - pointer file: ...".
בהרצה הראשונה cloudflared יורד (מאומת sha256) - יכול לקחת דקה. לשלוח לי את הפלט.

## הודעה 5 - תרגיל rotation
להשאיר את החלון פתוח, ובחלון PowerShell נוסף: taskkill /F /IM cloudflared.exe
צפוי: ה-supervisor מעלה מנהרה חדשה תוך שניות, וב-tunnel-state.json כתובת חדשה.
לשלוח לי את תוכן הקובץ (JSON קטן, ציבורי, לא סודי).

## הודעה 6 - אימות מקצה-לקצה (אצלי)
אני מריץ מה-sandbox מול הכתובת שב-state: הוכחת /health?nonce מול מפתח המכשיר, פקודה חתומה
בטוחה (קריאת קובץ מתוך תיקיית ה-scratch בלבד), ו-waitTerminal. מדווח תוצאות.

## Rollback מלא (2 צעדים, בלי שאריות)
1. בחלון ההרצה: Ctrl+C. אם cloudflared נשאר: taskkill /F /IM cloudflared.exe
2. למחוק את התיקייה %USERPROFILE%\gw-rehearsal - זהו.
לא נוגעים ב: firewall (bind מקומי בלבד), ראוטר, scheduled tasks, registry, האפליקציה המותקנת.

## סיכונים וגבולות
- החיבור היחיד החוצה: cloudflared -> edge של Cloudflare (חינם, בלי חשבון) + ההורדות בהתחלה.
- ה-pointer ציבורי מעצם תכנונו; כל פקודה דורשת חתימת שולח, כל קריאה read-auth חתום.
- מפתחות החזרה חד-פעמיים ומושמדים; תיקיית ה-roots היא scratch ריקה.
