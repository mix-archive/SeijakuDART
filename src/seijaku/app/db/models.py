import uuid
from datetime import UTC, datetime
from enum import StrEnum, auto

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, relationship
from sqlalchemy_utils import PasswordType, StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesGcmEngine

from seijaku.app.config import settings_dependency

Base = declarative_base()


class GUID(sa.TypeDecorator):
    """
    Platform-independent GUID type.

    Uses PostgreSQL's UUID type, otherwise uses CHAR(32), storing as stringified hex
    values.

    Credit: https://gist.github.com/gmolveau/7caeeefe637679005a7bb9ae1b5e421e
    """

    impl = sa.CHAR

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(sa.UUID())
        else:
            return dialect.type_descriptor(sa.CHAR(32))

    def process_bind_param(self, value, dialect):
        if dialect.name == "postgresql":
            return value

        match value:
            case uuid.UUID(hex=uuid_hex):
                return uuid_hex
            case None:
                return value
            case _:
                return f"{uuid.UUID(value):.32x}"

    def process_result_value(self, value, dialect):
        match value:
            case None | uuid.UUID:
                return value
            case _:
                return uuid.UUID(value)


class Clients(Base):
    __tablename__ = "clients"

    id_: Mapped[GUID] = mapped_column(
        primary_key=True, default=lambda: str(uuid.uuid4())
    )
    client_name: Mapped[str] = mapped_column(nullable=False, index=True, unique=True)
    encrypt_key: Mapped[str] = mapped_column(
        StringEncryptedType(
            sa.Unicode,
            key=lambda: bytes.fromhex(settings_dependency().encryption_key),
            engine=AesGcmEngine,
        ),
        nullable=False,
    )
    last_seen: Mapped[datetime | None] = mapped_column(nullable=True)
    last_from: Mapped[str | None] = mapped_column(nullable=True)

    owner_id: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id_"), nullable=False, index=True
    )
    owner: Mapped["Users"] = mapped_column(nullable=False, back_populates="clients")

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=sa.func.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, default=sa.func.now(UTC), onupdate=sa.func.now(UTC)
    )


class UserRoles(StrEnum):
    admin = auto()
    """Admin user, can do anything"""
    user = auto()
    """Normal user, can only manage their own clients"""
    client = auto()
    """Client user, can only manage their own client"""


class Users(Base):
    __tablename__ = "users"

    id_: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, index=True)
    role: Mapped[UserRoles] = mapped_column(nullable=False, index=True)
    username: Mapped[str] = mapped_column(nullable=False, index=True, unique=True)
    password: Mapped[str | None] = mapped_column(PasswordType(schemes=["argon2"]))
    jwt_secret: Mapped[bytes | None] = mapped_column(
        StringEncryptedType(
            sa.Unicode,
            key=lambda: bytes.fromhex(settings_dependency().encryption_key),
            engine=AesGcmEngine,
        )
    )

    clients: Mapped[list[Clients]] = relationship()

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=sa.func.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, default=sa.func.now(UTC), onupdate=sa.func.now(UTC)
    )
