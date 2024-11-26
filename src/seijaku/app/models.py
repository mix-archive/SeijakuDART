from datetime import UTC, datetime
from enum import StrEnum, auto

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, relationship
from sqlalchemy_utils import PasswordType, StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesGcmEngine

from seijaku.app.config import settings_dependency

Base = declarative_base()


class Clients(Base):
    __tablename__ = "clients"

    id_: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, index=True)
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

    created_by_id: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id_"), nullable=False, index=True
    )
    created_by: Mapped["Users"] = mapped_column(
        nullable=False, back_populates="clients"
    )

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default_factory=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, onupdate=datetime.now(UTC)
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

    clients: Mapped[list[Clients]] = relationship(back_populates="created_by")

    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default_factory=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, onupdate=datetime.now(UTC)
    )
