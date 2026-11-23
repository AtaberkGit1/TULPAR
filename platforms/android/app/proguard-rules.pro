-keep class org.yolac.app.YolacNative { *; }
-keep class org.yolac.app.YolacVpnService {
    public boolean protect(int);
}
