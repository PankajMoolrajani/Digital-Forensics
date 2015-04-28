from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import Base, Packets
from pyshark import *

class Database:
	def __init__(self, filename):
		self.processFile(filename)

	def processFile(self, filename):
		cap = FileCapture(filename)
		session = self.createDbSession()
		for pkt in cap: self.insert(pkt, session)
		session.commit()


	def insert(self, pkt, session):
		try:
			row = Packets(ip_src = pkt.ip.src, ip_dst = pkt.ip.dst, layer=pkt.highest_layer)
			session.add(row)
			
		except Exception as e:
			print "Exception in inserting"
			pass
		

	def createDbSession(self):
		engine = create_engine('sqlite:///tracefile.db')
		Base.metadata.create_all(engine)
		Base.metadata.bind = engine
		DBSession = sessionmaker(bind=engine)
		session = DBSession()
		return session