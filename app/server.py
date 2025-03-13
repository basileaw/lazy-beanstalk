# app.py

from fastapi import FastAPI
from terminaide import serve_terminal
import uvicorn

app = FastAPI()

serve_terminal(app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80)