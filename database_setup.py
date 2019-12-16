#!/usr/bin/env python3

# Initial setup of the quotes.db file

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Source(Base):
    __tablename__ = 'source'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }


class Quote(Base):
    __tablename__ = 'quote'

#   name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    source_id = Column(Integer, ForeignKey('source.id'))
    source = relationship(Source)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'description': self.description,
            'id': self.id,
        }


engine = create_engine('sqlite:///quotes.db')


Base.metadata.create_all(engine)
