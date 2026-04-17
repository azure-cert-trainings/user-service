"""
User Service - FastAPI Microservice
Handles user registration, authentication, and profile management
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import structlog
import logging
import time
from opentelemetry import metrics
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogRecordExporter # ConsoleLogExporter on versions earlier than 1.39.0
from opentelemetry._logs import set_logger_provider



from .database import engine, SessionLocal, Base
from .models import User
from .schemas import UserCreate, UserResponse, UserLogin, Token
from .auth import create_access_token, verify_token, get_password_hash, verify_password
from .config import settings
from .telemetry import configure_telemetry


# Create tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="User Service",
    description="Microservice for user management and authentication",
    version="1.0.0",
    docs_url=None,
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

configure_telemetry(app, engine)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize logging
logger = structlog.get_logger()
structlog.stdlib.recreate_defaults(log_level=logging.INFO)
###
# Set up OpenTelemetry logging (Manual instrumentation)
provider = LoggerProvider()
processor = BatchLogRecordProcessor(ConsoleLogRecordExporter())
provider.add_log_record_processor(processor)
# Sets the global default logger provider
set_logger_provider(provider)

handler = LoggingHandler(level=logging.INFO, logger_provider=provider)
logging.basicConfig(handlers=[handler], level=logging.INFO)
logger.info("Logging to test pipeline with infra tf creation.")
logger.info("Check first deployment.")



# OTel metrics: shared meter for this service
meter = metrics.get_meter("user-service")

# OTel metrics: HTTP request counter and latency histogram
REQUEST_COUNT = meter.create_counter(
    name="http.server.requests",
    description="Total HTTP requests handled by user-service",
    unit="1",
)
REQUEST_DURATION = meter.create_histogram(
    name="http.server.request.duration",
    description="HTTP request duration in seconds for user-service",
    unit="s",
)

# Security
security = HTTPBearer(auto_error=False)

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get current user
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    token = credentials.credentials
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user

@app.middleware("http")
async def add_process_time_header(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    # OTel metrics: record request volume and latency
    attributes = {
        "http.method": request.method,
        "http.route": request.url.path,
    }
    REQUEST_COUNT.add(1, attributes=attributes)
    REQUEST_DURATION.record(process_time, attributes=attributes)

    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Custom Swagger UI that persists auth across services"""
    html = f"""<!DOCTYPE html>
<html>
<head>
<link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css">
<link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
<title>{app.title} - Swagger UI</title>
</head>
<body>
<div id="swagger-ui">
</div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
<script>
const TOKEN_STORAGE_KEY = 'fastapi-demo-access-token';
const SECURITY_SCHEME_NAME = 'HTTPBearer';

function getStoredToken() {{
    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
}}

function applyStoredToken(ui) {{
    const token = getStoredToken();
    if (token && ui && ui.preauthorizeApiKey) {{
        ui.preauthorizeApiKey(SECURITY_SCHEME_NAME, token);
    }}
}}

const ui = SwaggerUIBundle({{
    url: '/users/openapi.json',
    dom_id: '#swagger-ui',
    layout: 'BaseLayout',
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    persistAuthorization: true,
    oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
    requestInterceptor: (request) => {{
        const token = getStoredToken();
        request.headers = request.headers || {{}};
        if (token && !request.headers.Authorization) {{
            request.headers.Authorization = `Bearer ${{token}}`;
        }}
        return request;
    }},
    responseInterceptor: (response) => {{
        try {{
            if (response.url && response.url.includes('/users/login') && typeof response.text === 'string') {{
                const payload = JSON.parse(response.text);
                if (payload.access_token) {{
                    window.localStorage.setItem(TOKEN_STORAGE_KEY, payload.access_token);
                    applyStoredToken(ui);
                }}
            }}
        }} catch (error) {{
            console.warn('Failed to persist JWT token.', error);
        }}
        return response;
    }},
    onComplete: () => applyStoredToken(ui),
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
    ],
}})
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "user-service"}

@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    logger.info("Registering new user", email=user.email)

    # Check if user already exists
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        hashed_password=hashed_password
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    logger.info("User registered successfully", user_id=db_user.id)
    return db_user

@app.post("/users/login", response_model=Token)
async def login_user(user_login: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return access token"""
    logger.info("User login attempt", email=user_login.email)

    # Find user by email
    db_user = db.query(User).filter(User.email == user_login.email).first()
    if not db_user or not verify_password(user_login.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Create access token
    access_token = create_access_token(data={"sub": str(db_user.id)})

    logger.info("User logged in successfully", user_id=db_user.id)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return current_user

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get user by ID"""
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return db_user

@app.get("/users", response_model=list[UserResponse])
async def list_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all users with pagination"""
    users = db.query(User).offset(skip).limit(limit).all()
    return users

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
