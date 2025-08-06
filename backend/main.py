from fastapi import FastAPI, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from auth import JWTBearer

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = JWTBearer()

@app.get("/")
def home():
    return {"message": "Secure backend running"}

@app.get("/protected", dependencies=[Depends(security)])
def protected(request: Request, response: Response):
    return {"message": "Access granted", "user": request.state.user["email"]}

@app.get("/health")
def health():
    return {"status": "ok"}