/*
 * Package name
 */
package targettest;


import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.*;


public class targettest extends Applet implements ExtendedLength
{
	static final short AES_BLOCK_SIZE = 16;
	/* Our AES instances */
	Aes aes128_instance = null;
	Aes aes192_instance = null;
	Aes aes256_instance = null;

	/* The key buffers */
	private byte[] key128 = null;
	private byte[] key192 = null;
	private byte[] key256 = null;


	/* Current AES key size */
	private byte current_aes_size = 0;

	/* Current data size */
	private short current_data_size = 0;

	/* Input and output */
	private byte[] data = null;
	private byte[] result = null;
	
        private static final byte INS_CASE1      = (byte) 0x01;
        private static final byte INS_CASE2      = (byte) 0x02;
        private static final byte INS_CASE3      = (byte) 0x03;
        private static final byte INS_CASE4      = (byte) 0x04;
        private static final byte INS_WAIT_EXT   = (byte) 0x05;

        private static final byte INS_SET_KEY          = (byte) 0x11;
        private static final byte INS_SET_DATA         = (byte) 0x12;
        private static final byte INS_GET_RESULT       = (byte) 0x13;
        private static final byte INS_GO               = (byte) 0x14;
        private static final byte INS_GET_KEY          = (byte) 0x15;
        private static final byte INS_GET_DATA         = (byte) 0x16;
        private static final byte INS_SET_DIR          = (byte) 0x17;
        private static final byte INS_SET_TYPE         = (byte) 0x18;

	/* Payload maximum size for encryption */
	private static final short MAX_PAYLOAD_SIZE = 128;

        public static void install(byte[] bArray, short bOffset, byte bLength)
        {
                new targettest();
        }

        protected targettest()
        {
		key128 = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		key192 = JCSystem.makeTransientByteArray((short) 24, JCSystem.CLEAR_ON_DESELECT);
		key256 = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(key128, (short) 0, (short) key128.length, (byte) 0);
		Util.arrayFillNonAtomic(key192, (short) 0, (short) key192.length, (byte) 0);
		Util.arrayFillNonAtomic(key256, (short) 0, (short) key256.length, (byte) 0);

		aes128_instance = new Aes((byte) 16);
		aes192_instance = new Aes((byte) 24);
		aes256_instance = new Aes((byte) 32);

                data   = JCSystem.makeTransientByteArray(MAX_PAYLOAD_SIZE, JCSystem.CLEAR_ON_DESELECT);
                result = JCSystem.makeTransientByteArray(MAX_PAYLOAD_SIZE, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
		Util.arrayFillNonAtomic(result, (short) 0, (short) result.length, (byte) 0);

                register();
        }


	/**********************************************************************************************/
	/*********** APDU cases related instructions **************************************************/
	/**********************************************************************************************/
        private void ins_case1(APDU apdu){
                byte buffer[] = apdu.getBuffer();
                /* In case 1 we expect neither data nor expected output */

                return;
        }

        private void ins_case2(APDU apdu){
                /* In case 2 we do not expect data, but return data */
                /* Answer the asked amount of data */
                short recvLe = apdu.setOutgoing();
                byte buffer[] = apdu.getBuffer();
                short asked_data = (short)(((short) (buffer[ISO7816.OFFSET_P1] & 0x00FF) << 8) ^  ((short) (buffer[ISO7816.OFFSET_P2] & 0x00FF)));
                if(recvLe < asked_data){
                        ISOException.throwIt((short) 0xBB03);
                }
                apdu.setOutgoingLength(asked_data);
                for(short i = 0; i < asked_data; i++){
                        data[0] = (byte) i;
                        apdu.sendBytesLong(data, (short) 0, (short) 1);
                }

                return;

        }

        private void ins_case3(APDU apdu){
                byte buffer[] = apdu.getBuffer();
                short receivedLen = apdu.setIncomingAndReceive();
                short OffsetCdata = apdu.getOffsetCdata();
                /* In case 3 we expect data */
                if(receivedLen == 0){
                        ISOException.throwIt((short) 0xCC01);
                }
                /* Get the input data */
                short echoOffset = (short) 0;
                while (receivedLen > 0) {
                        echoOffset += receivedLen;
                        receivedLen = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
                }

                return;
        }

        private void ins_case4(APDU apdu){
                short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
                /* In case 4 we expect data and return data */
                if(receivedLen == 0){
                        ISOException.throwIt((short) 0xDD01);
                }
                short asked_data = (short)(((short) (buffer[ISO7816.OFFSET_P1] & 0x00FF) << 8) ^  ((short) (buffer[ISO7816.OFFSET_P2] & 0x00FF)));
                if(asked_data == 0){
                        ISOException.throwIt((short) 0xDD02);
                }
                /* Get the input data */
                short echoOffset = (short) 0;
                while (receivedLen > 0) {
                        echoOffset += receivedLen;
                        receivedLen = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
                }
                /* Answer the asked amount of data */
                short recvLe = apdu.setOutgoing();
                /*if(recvLe < asked_data){
                        ISOException.throwIt((short) 0xDD03);
                }*/
                apdu.setOutgoingLength(asked_data);
                for(short i = 0; i < asked_data; i++){
                        data[0] = (byte) i;
                        apdu.sendBytesLong(data, (short) 0, (short) 1);
                }

                return;
        }

	private void ins_wait_ext(APDU apdu){
                short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		short waitTime = (short)(((short) (buffer[ISO7816.OFFSET_P1] & 0x00FF) << 8) ^  ((short) (buffer[ISO7816.OFFSET_P2] & 0x00FF)));
		/* Wait */
                for (short i = 0; i < waitTime; i++)
                    for (short j = 0; j < 1000; j++)
                        ;

		return;
	}

	/**********************************************************************************************/
	/*********** AES related instructions *********************************************************/
	/**********************************************************************************************/
	private void ins_go(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* No data expected */
		if(receivedLen != 0){
			ISOException.throwIt((short) 0x6601);
		}
		/* Sanity check */
		if(current_data_size == 0){
			ISOException.throwIt((short) 0x6602);	
		}
		/* Launch the operation */
		short size;
		switch(current_aes_size){
			case 16:
				size = aes128_instance.aes(data, (short) 0, current_data_size, result, (short) 0);
				break; 
			case 24:
				size = aes192_instance.aes(data, (short) 0, current_data_size, result, (short) 0);
				break; 
			case 32:
				size = aes256_instance.aes(data, (short) 0, current_data_size, result, (short) 0);
				break; 
			default:
				ISOException.throwIt((short) 0x6603);
		}
		return;
	}
	
	private void ins_setKey(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* Check size */
		switch(receivedLen){
			case 16:
				/* Get the key */
				Util.arrayCopyNonAtomic(buffer, OffsetCdata, key128, (short) 0, (short) 16);
				aes128_instance.aes_set_key(key128);
				current_aes_size = 16;
				break;
			case 24:
				/* Get the key */
				Util.arrayCopyNonAtomic(buffer, OffsetCdata, key192, (short) 0, (short) 24);
				aes192_instance.aes_set_key(key192);
				current_aes_size = 24;
				break;
			case 32:
				/* Get the key */
				Util.arrayCopyNonAtomic(buffer, OffsetCdata, key256, (short) 0, (short) 32);
				aes256_instance.aes_set_key(key256);
				current_aes_size = 32;
				break;
			default:
				/* Bad key length */
				ISOException.throwIt((short) 0x6601);
		}

		return;
	}

	private void ins_getKey(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* No data expected */
		if(receivedLen != 0){
			ISOException.throwIt((short) 0x6601);
		}
		/* Send back the key */
		switch(current_aes_size){
			case 16:
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) 16);
				apdu.sendBytesLong(key128, (short) 0, (short) 16);
				return;
			case 24:
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) 24);
				apdu.sendBytesLong(key192, (short) 0, (short) 24);
				return;
			case 32:
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) 32);
				apdu.sendBytesLong(key256, (short) 0, (short) 32);
				return;
			default:
				ISOException.throwIt((short) 0x6602);
		}
		return;
	}

	private void ins_getData(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* No data expected */
		if(receivedLen != 0){
			ISOException.throwIt((short) 0x6601);
		}
		/* Send back the data */
		apdu.setOutgoing();
		apdu.setOutgoingLength(current_data_size);
		apdu.sendBytesLong(data, (short) 0, current_data_size);
		return;
	}

	private void ins_setData(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* Check length */
		if(receivedLen % Aes.AES_BLOCK_SIZE != 0){
			ISOException.throwIt((short) 0x6601);	
		}
		if(receivedLen > data.length){
			ISOException.throwIt((short) 0x6602);	
		}
		/* Set our internal data */
		Util.arrayCopyNonAtomic(buffer, OffsetCdata, data, (short) 0, receivedLen);
		current_data_size = receivedLen;
		
		return;
	}

	private void ins_getResult(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* No data expected */
		if(receivedLen != 0){
			ISOException.throwIt((short) 0x6601);
		}
		/* Send back the result */
		apdu.setOutgoing();
		apdu.setOutgoingLength(current_data_size);
		apdu.sendBytesLong(result, (short) 0, current_data_size);

		return;
	}

	private void ins_setDir(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* One byte expected */
		if(receivedLen != 1){
			ISOException.throwIt((short) 0x6601);
		}
		byte dir = buffer[OffsetCdata];
		switch(dir){
			case Aes.ENCRYPT:
				/* Set the dir */
				aes128_instance.aes_set_dir(Aes.ENCRYPT);
				aes192_instance.aes_set_dir(Aes.ENCRYPT);
				aes256_instance.aes_set_dir(Aes.ENCRYPT);
				break;
			case Aes.DECRYPT:
				/* Set the dir */
				aes128_instance.aes_set_dir(Aes.DECRYPT);
				aes192_instance.aes_set_dir(Aes.DECRYPT);
				aes256_instance.aes_set_dir(Aes.DECRYPT);
				break;
			default:
				ISOException.throwIt((short) 0x6602);
		}
		return;
	}

	private void ins_setType(APDU apdu){
		short receivedLen = apdu.setIncomingAndReceive();
                byte buffer[] = apdu.getBuffer();
                short OffsetCdata = apdu.getOffsetCdata();
		/* One byte expected */
		if(receivedLen != 1){
			ISOException.throwIt((short) 0x6601);
		}
		byte type = buffer[OffsetCdata];
		switch(type){
			case Aes.AES_HARD:
				/* Set the dir */
				aes128_instance.aes_set_type(Aes.AES_HARD);
				aes192_instance.aes_set_type(Aes.AES_HARD);
				aes256_instance.aes_set_type(Aes.AES_HARD);
				break;
			case Aes.AES_SOFT:
				/* Set the dir */
				aes128_instance.aes_set_type(Aes.AES_SOFT);
				aes192_instance.aes_set_type(Aes.AES_SOFT);
				aes256_instance.aes_set_type(Aes.AES_SOFT);
				break;
			default:
				ISOException.throwIt((short) 0x6602);
		}
		return;
	}

        public void process(APDU apdu)
        {
                byte[] buffer = apdu.getBuffer();

                if (selectingApplet()){
                        return;
                }

                if(buffer[ISO7816.OFFSET_CLA] != (byte)0x00){
                        ISOException.throwIt((short) 0x6660);
                }

                /* Now handle our specific APDUs */
                switch (buffer[ISO7816.OFFSET_INS]){
			/* APDU cases related instructions */
                        case INS_CASE1:
                                ins_case1(apdu);
                                return;
                        case INS_CASE2:
                                ins_case2(apdu);
                                return;
                        case INS_CASE3:
                                ins_case3(apdu);
                                return;
                        case INS_CASE4:
                                ins_case4(apdu);
                                return;
                        case INS_WAIT_EXT:
                                ins_wait_ext(apdu);
                                return;
			/* AES related instructions */
                       case INS_GO:
                                ins_go(apdu);
                                return;
                       case INS_SET_KEY:
                                ins_setKey(apdu);
                                return;
			case INS_SET_DATA:
                                ins_setData(apdu);
                                return;	
                        case INS_GET_RESULT:
                                ins_getResult(apdu);
                                return;
                        case INS_GET_DATA:
                                ins_getData(apdu);
                                return;
                        case INS_GET_KEY:
                                ins_getKey(apdu);
                                return;
                        case INS_SET_DIR:
                                ins_setDir(apdu);
                                return;
                        case INS_SET_TYPE:
                                ins_setType(apdu);
                                return;

                        default:
                               /* Send unsupported APDU */
                               ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }

        }
}
