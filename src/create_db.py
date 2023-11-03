import sqlite3

import objects
import constants as const

def main():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        cur.execute("""CREATE TABLE IF NOT EXISTS transaction (
        id TEXT PRIMARY KEY,
        height INTEGER,
        inputs references inputs(id),
        outputs references outputs(id),
        block references block(id)
        )""")

        cur.execute("""CREATE TABLE IF NOT EXISTS outputs (
        id TEXT references object(id) PRIMARY KEY,
        pubkey TEXT,
        val INTEGER)
        """)

        cur.execute("""CREATE TABLE IF NOT EXISTS inputs (
        id TEXT references object(id) PRIMARY KEY,
        pubkey TEXT,
        val INTEGER)
        """)

        cur.execute("""CREATE TABLE IF NOT EXISTS block(
        id TEXT PRIMARY KEY,
        target TEXT,
        created TEXT,
        miner TEXT,
        nonce TEXT,
        note TEXT,
        previd INTEGER references block(id)
        """)

        cur.execute(f"""INSERT into block (id, target, created, miner, nonce, note, previd)
                    values ({const.GENESIS_BLOCK_ID},{const.GENESIS_BLOCK.get("T")},{const.GENESIS_BLOCK.get("created")},{const.GENESIS_BLOCK.get("miner")}, 
                    {const.GENESIS_BLOCK.get("nonce")}, {const.GENESIS_BLOCK.get("note")}, null)""")

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()


if __name__ == "__main__":
    main()
