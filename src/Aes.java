package targettest;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Aes { 
	static final short AES_BLOCK_SIZE = 16;
	/* AES size */
	private byte aes_key_len = 0;
	/* AES type: software or hardware */
	private byte type;
	static final byte AES_HARD = 0;
	static final byte AES_SOFT = 1;
	/* Direction */
	private byte dir;
	static final byte ENCRYPT = 0;
	static final byte DECRYPT = 1;
	/* Our internal instances */
	private Cipher cipherAES = null;
	private AESKey aesKey = null;
	/* Internal value of the key */
	private byte[] aes_key = null;
	private boolean aes_key_init = false;
	/* Internal value for state */
	private byte[] aes_state = null;

	protected Aes(byte key_len){
		try{
			/* Initialize our AES context */
			short key_builder = 0;
			switch(key_len){
				case 16:
					key_builder = KeyBuilder.LENGTH_AES_128;
					aes_key_len = 16;
					break;
				case 24:
					key_builder = KeyBuilder.LENGTH_AES_192;
					aes_key_len = 24;
					break;
				case 32:
					key_builder = KeyBuilder.LENGTH_AES_256;
					aes_key_len = 32;
					break;
				default:
					CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, key_builder, false);
			/* Initialize our cipher */
			cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
			/* Allocations */
			aes_key = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
			aes_state = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		}
                catch(CryptoException exception)
                {
                    switch(exception.getReason()){
                        case CryptoException.ILLEGAL_USE:
                                ISOException.throwIt((short) 0xAAD0);
                                break;
                        case CryptoException.ILLEGAL_VALUE:
                                ISOException.throwIt((short) 0xAAD1);
                                break;
                        case CryptoException.INVALID_INIT:
                                ISOException.throwIt((short) 0xAAD2);
                                break;
                        case CryptoException.NO_SUCH_ALGORITHM:
                                ISOException.throwIt((short) 0xAAD3);
                                break;
                        case CryptoException.UNINITIALIZED_KEY:
                                ISOException.throwIt((short) 0xAAD4);
                                break;
                        default:
                                ISOException.throwIt((short) 0xAAD5);
                                break;
                        }
                }
	}

	public void aes_set_key(byte[] key){
		/* Sanity check on the key size */
		if(key.length != aes_key_len){
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		/* Set our internal keys */
		aesKey.setKey(key, (short) 0);
		Util.arrayCopyNonAtomic(key, (short) 0, aes_key, (short) 0, (short) key.length);
		/* Default is encryption */
		dir = ENCRYPT;
		cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
		/* Default is AES hard */
		type = AES_HARD;
		/* Init OK */
		aes_key_init = true;
	}

	/* Get key size */
	public short aes_get_size(){
		return aes_key_len;
	}
	
	/* Modify the type */
	public void aes_set_type(byte asked_type){
		switch(asked_type){
			case AES_HARD:
			case AES_SOFT:
				type = asked_type;
				break;
			default:
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
	}

	/* Modify the direction */
	public void aes_set_dir(byte asked_dir){
		dir = asked_dir;
	}


	public short aes(byte[] input, short inputoffset, short inputlen, byte[] output, short outputoffset){
                if(aes_key_init == false){
	                CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
                }
		/* Switch direction if we were asked to */
		switch(dir){
			case ENCRYPT:
				cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
				break;
			case DECRYPT:
				cipherAES.init(aesKey, Cipher.MODE_DECRYPT);
				break;
			default:
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		/* If input and output are the same and size is block aligned (which is always the case here since we do not handle padding),
		 * they should not overlap ... See the Javacard API documentation for Cipher.update */
		if(input == output){
			if((inputoffset < outputoffset) && (outputoffset < (short)(inputoffset + inputlen))){
				CryptoException.throwIt(CryptoException.ILLEGAL_USE);
			}
		}
		/* We ony support block aligned sizes */
		if(inputlen % AES_BLOCK_SIZE != 0){
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		if(type == AES_HARD){
			/* Hardware AES */
			return cipherAES.doFinal(input, inputoffset, inputlen, output, outputoffset);
		}
		else if(type == AES_SOFT) {
			/* Software AES: TODO */
			return 0;
		}
		else{
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		return 0;
	}
}
