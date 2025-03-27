Java.perform(function () {
    var TargetClass = Java.use('com.ldjSxw.heBbQd.a.b');
    TargetClass.k.implementation = function () {
        send("[+] Intercepted com.ldjSxw.heBbQd.a.b.k()");
        return false;
    };
});