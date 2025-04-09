from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import tempfile
import os
import logging
from models import SSHKey
from ssh_sk_attest import verify_attestation, parse_pubkey

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SSH SK Attestation API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/key")
async def verify_ssh_attestation(
    pubkey: UploadFile = File(...),
    attestation: UploadFile = File(...),
    challenge: UploadFile = File(...)
):
        pubkey_content = await pubkey.read()
        attestation_content = await attestation.read()
        challenge_content = await challenge.read()
                
        try:
            # Verify the attestation using the library
            logger.info("Verifying attestation...")
            result = verify_attestation(
                pubkey_content,
                attestation_content,
                challenge_content
            )
            
            if result.valid:
                # Store the verified key in the database
                logger.info("Attestation valid, storing key in database...")
                try:
                    key_type, pubkey, comment = pubkey_content.decode().strip().split(" ")
                    key_id = SSHKey.create(
                        key_type=key_type,
                        public_key=pubkey,
                        comment=comment
                    )
                    logger.info(f"Key stored successfully with ID: {key_id}")
                    return {"status": "success", "message": "Key verified and stored successfully"}
                except ValueError as e:
                    logger.error(f"Database error: {str(e)}")
                    raise HTTPException(status_code=400, detail=str(e))
                except Exception as e:
                    logger.error(f"Database error: {str(e)}")
                    raise HTTPException(status_code=500, detail=str(e))
            else:
                logger.error(f"Attestation invalid: {result.error}")
                raise HTTPException(status_code=400, detail=result.error)
                
        except Exception as e:
            logger.error(f"Error during attestation: {str(e)}")
            raise HTTPException(status_code=400, detail=str(e))


@app.get("/key")
async def get_key(pubkey: str = Query(..., description="SSH public key")):
    """Get a public key from the database."""
    logger.info("Getting key...")
    try:
        key = SSHKey.get_by_public_key(pubkey)
        if key:
            logger.info("Key found")
            return dict(key)
        else:
            logger.info("Key not found")
            return JSONResponse(
                status_code=404,
                content={"detail": "Key not found"}
            )
    except Exception as e:
        logger.error(f"Error getting key: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/keys")
async def list_keys():
    logger.info("Listing all keys...")
    try:
        keys = SSHKey.get_all()
        logger.info(f"Found {len(keys)} keys")
        return [dict(key) for key in keys]
    except Exception as e:
        logger.error(f"Error listing keys: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 