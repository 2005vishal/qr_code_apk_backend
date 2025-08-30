import os
import base64
from datetime import datetime, timedelta
from typing import List

import pyodbc
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi import Body

load_dotenv()

# =================== DB CONFIG ===================
DB_SERVER = os.getenv("DB_SERVER", "localhost\\SQLEXPRESS")
DB_NAME   = os.getenv("DB_NAME", "studentattendanceDB")
DB_USER   = os.getenv("DB_USER", "sa")
DB_PASS   = os.getenv("DB_PASS", "Dabra12@")
DB_DRIVER = os.getenv("DB_DRIVER", "ODBC Driver 17 for SQL Server")

JWT_SECRET = os.getenv("JWT_SECRET", "53b60c5b707b8de38f0a5a244c88c37147140c2bcdfb889a4d9e5f89962dff1d")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 1440))

# =================== FASTAPI APP ===================
app = FastAPI(
    title="Student Attendance API",
    swagger_ui_parameters={"persistAuthorization": True}
)

# Allow CORS
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production restrict to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =================== MODELS ===================
class LoginRequest(BaseModel):
    roll: str
    pin: str

class StudentProfile(BaseModel):
    roll: str
    name: str
    branch: str
    semester: str
    issue_valid: str
    photo: str   # will now be URL instead of base64

class AttendanceRecord(BaseModel):
    date: str
    status: str

# =================== DB CONNECTION ===================
def get_connection():
    conn_str = (
        f"DRIVER={{{DB_DRIVER}}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_NAME};"
        f"UID={DB_USER};"
        f"PWD={DB_PASS};"
    )
    try:
        return pyodbc.connect(conn_str)
    except pyodbc.Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {str(e)}")

# =================== AUTH HELPERS ===================
def create_jwt_token(roll: str):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {"roll": roll, "exp": int(expire.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# =================== SECURITY ===================
security = HTTPBearer()

def get_current_roll(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_jwt_token(token)
    return payload["roll"]

# =================== API ENDPOINTS ===================
@app.post("/api/login")
def login(req: LoginRequest):
    roll = req.roll.strip()
    pin = req.pin.strip()

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT roll FROM Students WHERE LTRIM(RTRIM(roll))=? AND LTRIM(RTRIM(pin))=?",
            (roll, pin)
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid roll or PIN")

    token = create_jwt_token(roll)
    return {"token": token}


# ✅ PROFILE ENDPOINT (now returns URL for photo)
@app.get("/api/profile", response_model=StudentProfile)
def get_profile(roll: str = Depends(get_current_roll)):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT roll, name, branch, semester, issue_valid, photo FROM Students WHERE roll=?",
            (roll,)
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Student not found")

    photo_url = ""
    if row[5]:
        # Instead of base64, return an API URLq
        photo_url = f"http://127.0.0.1:8000/api/photo/{roll}"

    return StudentProfile(
        roll=str(row[0]),
        name=str(row[1]),
        branch=str(row[2]),
        semester=str(row[3]),
        issue_valid=str(row[4]),
        photo=photo_url
    )


# ✅ Serve photo by roll
@app.get("/api/photo/{roll}")
def get_student_photo(roll: str):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT photo FROM Students WHERE roll=?", (roll,))
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not row or not row[0]:
        raise HTTPException(status_code=404, detail="Photo not found")

    photo_path = row[0]
    if not os.path.exists(photo_path):
        raise HTTPException(status_code=404, detail="File not found on server")

    return FileResponse(photo_path)


@app.get("/api/attendance", response_model=List[AttendanceRecord])
def get_attendance(roll: str = Depends(get_current_roll)):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT date, status 
            FROM Attendance 
            WHERE roll=? AND date >= DATEADD(MONTH, -4, GETDATE())
            ORDER BY date DESC
            """,
            (roll,)
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    records = [
        {"date": row[0].strftime("%Y-%m-%d"), "status": row[1]}
        for row in rows
    ]
    return records
# in FastAPI backend

#---------------------------------forgot pin-----------------------------------------

@app.post("/api/forgot-pin")
def forgot_pin(data: dict = Body(...)):
    roll = data.get("roll")
    dob = data.get("dob")  # expected format: YYYY-MM-DD
    new_pin = data.get("new_pin")

    if not roll or not dob or not new_pin:
        raise HTTPException(status_code=400, detail="Missing fields")

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT dob FROM Students WHERE roll=?", (roll,)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Student not found")

        db_dob = str(row[0]).split(" ")[0]  # keep date only
        if db_dob != dob:
            raise HTTPException(status_code=401, detail="DOB does not match")

        cursor.execute(
            "UPDATE Students SET pin=? WHERE roll=?",
            (new_pin, roll)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    return {"message": "PIN reset successful"}
