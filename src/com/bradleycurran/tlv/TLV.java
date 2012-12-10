package com.bradleycurran.tlv;

import java.util.LinkedList;
import java.util.List;

public class TLV {

    public class TLVException extends Exception {

        private static final long serialVersionUID = -2427261641980591073L;
    }

    private static final int TAG_TOPLEVEL = 0xFFFF;

    private byte[] mValue;

    private int mIndex;

    private int mLength;

    private int mTag;

    private List<TLV> mChildren;

    public TLV(byte[] value) throws TLVException {
        this(value, 0, value.length, TAG_TOPLEVEL);
    }

    private TLV(byte[] value, int index, int length, int tag) throws TLVException {
        if (value == null)
            throw new IllegalArgumentException("value must not be null");

        mValue = value;
        mIndex = index;
        mLength = length;
        mTag = tag;
        mChildren = new LinkedList<TLV>();

        if (isConstructed()) {
            parse();
        }
    }

    public int getTag() {
        return mTag;
    }

    public byte[] getValue() {
        byte[] newArray = new byte[mLength];
        System.arraycopy(mValue, mIndex, newArray, 0, mLength);
        return newArray;
    }

    public List<TLV> getChildren() {
        return mChildren;
    }

    public boolean isConstructed() {
        final int CONSTRUCTED_BIT = 0x20;
        return (getFirstTagByte(mTag) & CONSTRUCTED_BIT) != 0;
    }

    private void parse() throws TLVException {
        int index = mIndex;
        int endIndex = mIndex + mLength;

        while (index < endIndex) {
            int tag = (mValue[index++] & 0xFF);

            if (tag == 0x00 || tag == 0xFF)
                continue;

            if (tagHasMultipleBytes(tag)) {
                tag <<= 8;
                tag |= (mValue[index++] & 0xFF);

                if (tagHasAnotherByte(tag)) {
                    tag <<= 8;
                    tag |= (mValue[index++] & 0xFF);
                }

                if (tagHasAnotherByte(tag))
                    throw new TLVException();
            }

            int length = (mValue[index++] & 0xFF);

            if (length >= 0x80) {
                int numLengthBytes = (length & 0x7F);

                if (numLengthBytes > 3)
                    throw new TLVException();

                length = 0;

                for (int i = 0; i < numLengthBytes; i++) {
                    length <<= 8;
                    length |= (mValue[index++] & 0xFF);
                }
            }

            TLV tlv = new TLV(mValue, index, length, tag);
            mChildren.add(tlv);
            index += tlv.getLength();
        }
    }

    private int getLength() {
        return mLength;
    }

    private static int getFirstTagByte(int tag) {
        while (tag > 0xFF)
            tag >>= 8;

        return tag;
    }

    private static boolean tagHasMultipleBytes(int tag) {
        final int MULTIBYTE_TAG_MASK = 0x1F;
        return (tag & MULTIBYTE_TAG_MASK) == MULTIBYTE_TAG_MASK;
    }

    private static boolean tagHasAnotherByte(int tag) {
        final int NEXT_BYTE = 0x80;
        return (tag & NEXT_BYTE) != 0;
    }
}
