"""Local API used by the browser extension to check the current page URL."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.analyzer import analyze_url


app = FastAPI(title="Local Phishing Link Checker", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^chrome-extension://[a-p]{32}$",
    allow_methods=["POST"],
    allow_headers=["content-type"],
)


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


@app.get("/health")
def health():
    return {"status": "ok", "message": "Local link checker is running"}


@app.post("/analyze-url")
def analyze_url_endpoint(request: URLRequest):
    return analyze_url(request.url)

