from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class Packets(Base):
	__tablename__ = 'packets'
	id = Column(Integer, primary_key=True)
	ip_src = Column(String(11), nullable=False)
	ip_dst = Column(String(11), nullable=False)

	