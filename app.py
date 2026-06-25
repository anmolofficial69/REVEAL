from fastapi import FastAPI,Header
from jose import jwt
from fastapi import HTTPException
from datetime import datetime, timedelta
from jose import ExpiredSignatureError
from passlib.context import CryptContext
from sqlalchemy import create_engine
from pydantic import BaseModel
import psycopg2

from fastapi.middleware.cors import CORSMiddleware

app=FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

class registration(BaseModel):
    username:str
    password:str

class Posts(BaseModel):
    content:str

import os
import psycopg2

SECRET_KEY = os.getenv("SECRET_KEY")

DATABASE_URL = os.getenv("DATABASE_URL")

engine=create_engine(DATABASE_URL)

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    return conn, cursor

@app.post("/register")
def register(users:registration):
    conn,cursor=get_db()
    hashed_password=pwd_context.hash(users.password)
    try:
        cursor.execute(
            """insert into users (username,password)
               values (%s,%s)""",
               (users.username,hashed_password)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return {"message":"user registered :)"}
    except:
        conn.rollback()
        raise HTTPException(status_code=400,detail="Username already taken")

@app.post("/login")
def login(users:registration):
    conn,cursor=get_db()
    cursor.execute(
        """select id,username,password
           from users
           where username=%s""",
           (users.username,)
    )
    db_user=cursor.fetchone()
    if db_user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid Credentials"
        )
    if not pwd_context.verify(users.password,db_user[2]):
        raise HTTPException(
            status_code=401,
            detail="Invalid Credentials"
        )
    token=jwt.encode(
        {
            "user_id":db_user[0],
            "username":db_user[1],
            "exp":datetime.utcnow() + timedelta(days=2)
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    cursor.close()
    conn.close()
    return {"token":token}
       
@app.post("/posts")
def create_post(posts:Posts,authorization:str=Header()):
    conn,cursor=get_db()
    token=authorization.split(" ")[1]
    payload=jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"]
    )
    user_id=payload["user_id"]

    cursor.execute(
        """insert into posts(content,user_id)
            values (%s,%s)""",
            (posts.content,user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"message":"post created"}
    

@app.get("/posts")
def show_post():
    conn,cursor=get_db()
    cursor.execute(
        """SELECT posts.id, posts.content, users.username, COUNT(likes.user_id) AS like_count
           FROM posts
           JOIN users ON posts.user_id = users.id
           LEFT JOIN likes ON posts.id = likes.post_id
           GROUP BY posts.id, posts.content, users.username"""
    )
    show = cursor.fetchall()
    cursor.close()
    conn.close()
    return [{"id": r[0], "content": r[1], "likes": r[2]} for r in show]


@app.delete("/post/{id}")
def delete(id:int,authorization:str=Header()):
    conn,cursor=get_db()
    
    token=authorization.split(" ")[1]
    payload=jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"]
    )
    user_id=payload["user_id"]

    cursor.execute(
        """DELETE FROM posts
            WHERE id=%s
            AND user_id=%s""",
            (id,user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"message":"post deleted"}

@app.post("/post/{id}/like")
def like(id:int,authorization : str=Header()):
    conn,cursor=get_db()
    token=authorization.split(" ")[1]
    payload=jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"]
    )
    user_id=payload["user_id"]

    cursor.execute(
        """insert into likes(post_id,user_id)
           values(%s,%s)""",
        (id,user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"message":"post is liked"}

@app.delete("/post/{id}/like")
def del_like(id:int,authorization : str=Header()):
    conn,cursor=get_db()
    token=authorization.split(" ")[1]
    payload=jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"]
    )
    user_id=payload["user_id"]

    cursor.execute(
        """delete from likes
            where post_id=%s
            and user_id=%s""",
        (id,user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"message":"post like is deleted"}
