from fastapi import APIRouter

from .auth import UserSessionDependency, login
from .db.session import DatabaseSessionDependency
from .models import ClientCreation, SessionCreation, SessionCreationResponse

router = APIRouter(prefix="/api")


@router.post("/session")
async def create_session(
    model: SessionCreation, db: DatabaseSessionDependency
) -> SessionCreationResponse:
    session, token = await login(model.username, model.password, db)
    return SessionCreationResponse(session_data=session, token=token)


@router.put("/client")
async def create_client(
    model: ClientCreation, user: UserSessionDependency, db: DatabaseSessionDependency
):
    pass
