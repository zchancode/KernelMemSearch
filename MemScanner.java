package com.example.hack;

import android.util.Log;

public class MemScanner {
    static {
        System.loadLibrary("hack");
    }

    public native long[] searchMemory(int pid, byte[] pattern, int maxResults);
    public native byte[] readMemory(int pid, long address, int size);

    public long[] search(int pid, String pattern, int maxResults) {
        byte[] patternBytes = hexStringToByteArray(pattern);
        long[] results = searchMemory(pid, patternBytes, maxResults);
        return results;
    }

    public byte[] read(int pid, long address, int size) {
        return readMemory(pid, address, size);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
