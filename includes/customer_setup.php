<?php


class MiniorangeSAMLIdpCustomer
{
    public $email;
    public $phone;
    public $customerKey;
    public $transactionId;
    public $password;
    public $otpToken;
    private $defaultCustomerId;
    private $defaultCustomerApiKey;
    public function __construct($ZK, $kx, $ct, $dr)
    {
        $this->email = $ZK;
        $this->phone = $kx;
        $this->password = $ct;
        $this->otpToken = $dr;
        $this->defaultCustomerId = "\61\x36\x35\65\65";
        $this->defaultCustomerApiKey = "\146\x46\144\62\x58\x63\x76\x54\107\104\145\155\x5a\166\142\167\x31\142\143\125\x65\163\x4e\x4a\127\105\x71\113\x62\142\125\161";
    }
    public function checkCustomer()
    {
        if (IDPUtilities::isCurlInstalled()) {
            goto HZ;
        }
        return json_encode(array("\163\164\141\x74\x75\x73" => "\103\125\x52\x4c\137\x45\x52\x52\117\x52", "\163\x74\141\164\x75\x73\x4d\145\163\163\x61\147\145" => "\74\141\x20\150\162\145\x66\75\x22\150\164\164\160\72\x2f\57\160\150\160\x2e\156\x65\164\57\x6d\141\156\165\x61\154\x2f\x65\x6e\57\x63\x75\162\x6c\x2e\151\156\x73\164\141\154\154\141\164\x69\x6f\156\x2e\160\x68\x70\42\76\x50\110\120\40\143\x55\x52\114\x20\145\x78\x74\x65\x6e\163\x69\x6f\156\x3c\57\141\x3e\40\x69\x73\40\156\157\164\40\151\x6e\x73\x74\x61\154\154\145\x64\40\x6f\x72\40\144\x69\163\x61\x62\154\145\x64\56"));
        HZ:
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\x2f\x6d\x6f\141\163\x2f\162\x65\163\164\57\143\165\x73\x74\157\x6d\145\x72\x2f\143\150\145\x63\x6b\x2d\151\x66\x2d\145\x78\x69\x73\164\163";
        $yG = curl_init($zi);
        $ZK = $this->email;
        $xE = array("\x65\x6d\141\x69\x6c" => $ZK);
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($yG, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\157\156\164\145\156\164\x2d\x54\x79\160\x65\x3a\40\141\x70\x70\x6c\x69\143\141\x74\x69\x6f\156\57\152\163\157\156", "\143\x68\x61\162\163\x65\x74\72\40\x55\x54\x46\40\55\x20\70", "\101\165\x74\x68\157\162\x69\x7a\x61\x74\151\x6f\x6e\x3a\x20\102\141\x73\x69\143"));
        curl_setopt($yG, CURLOPT_POST, TRUE);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto t2;
        }
        $D6 = array("\x25\155\x65\164\x68\157\144" => "\x63\150\x65\x63\153\x43\165\x73\x74\x6f\x6d\145\162", "\45\x66\151\x6c\x65" => "\143\x75\x73\x74\157\155\145\x72\137\x73\x65\x74\165\x70\56\x70\150\x70", "\x25\145\162\x72\157\x72" => curl_error($yG));
        watchdog("\x6d\151\x6e\x69\157\x72\x61\x6e\147\145\137\163\141\155\x6c\x5f\x69\144\160", "\x45\162\162\157\x72\x20\141\164\x20\45\155\145\164\x68\x6f\144\40\157\146\40\x25\x66\151\x6c\x65\x3a\x20\x25\145\162\x72\x6f\162", $D6);
        t2:
        curl_close($yG);
        return $ES;
    }
    public function createCustomer()
    {
        if (IDPUtilities::isCurlInstalled()) {
            goto a4;
        }
        return json_encode(array("\163\164\x61\164\x75\163\x43\x6f\144\x65" => "\105\x52\x52\117\122", "\163\x74\x61\x74\165\x73\115\x65\x73\x73\141\x67\x65" => "\x2e\40\x50\154\145\141\163\145\40\143\x68\x65\x63\x6b\x20\x79\x6f\165\162\40\143\x6f\x6e\x66\x69\x67\x75\x72\141\x74\x69\x6f\156\x2e"));
        a4:
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\57\155\x6f\141\x73\x2f\x72\x65\163\164\57\143\x75\x73\x74\x6f\155\145\x72\x2f\141\144\x64";
        $yG = curl_init($zi);
        $xE = array("\143\x6f\x6d\160\141\156\x79\116\141\x6d\x65" => $_SERVER["\x53\x45\x52\x56\x45\x52\137\x4e\x41\x4d\105"], "\141\162\x65\141\117\146\x49\156\x74\145\162\145\163\164" => "\x44\122\x55\120\x41\x4c\40\x49\x44\120\x20\x4d\157\x64\x75\x6c\x65", "\x65\x6d\x61\x69\154" => $this->email, "\160\150\157\156\x65" => $this->phone, "\x70\141\x73\x73\x77\157\162\x64" => $this->password);
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($yG, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\x6f\156\164\145\156\x74\55\x54\x79\x70\x65\72\40\x61\160\160\154\x69\x63\x61\x74\151\x6f\x6e\x2f\x6a\163\x6f\156", "\143\x68\x61\162\x73\x65\x74\x3a\40\125\124\106\x20\x2d\40\70", "\101\x75\164\x68\157\x72\151\172\141\x74\x69\x6f\156\x3a\40\102\141\163\151\x63"));
        curl_setopt($yG, CURLOPT_POST, TRUE);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto Sw;
        }
        $D6 = array("\45\x6d\x65\164\x68\x6f\x64" => "\143\162\x65\141\x74\x65\103\x75\x73\164\157\x6d\145\x72", "\x25\x66\x69\x6c\145" => "\143\165\x73\164\157\x6d\145\x72\137\163\x65\164\165\x70\x2e\160\x68\x70", "\45\145\x72\162\x6f\x72" => curl_error($yG));
        watchdog("\x6d\151\x6e\x69\157\x72\x61\156\x67\145\x5f\x73\141\x6d\154\137\x69\x64\160", "\105\x72\x72\157\x72\40\x61\164\x20\45\x6d\145\x74\x68\157\x64\40\x6f\x66\40\x25\146\151\x6c\x65\72\x20\45\145\x72\x72\x6f\x72", $D6);
        Sw:
        curl_close($yG);
        return $ES;
    }
    public function getCustomerKeys()
    {
        if (IDPUtilities::isCurlInstalled()) {
            goto SM;
        }
        return json_encode(array("\141\160\151\113\x65\x79" => "\103\125\122\114\137\x45\122\122\x4f\122", "\x74\157\153\145\x6e" => "\x3c\x61\x20\150\x72\x65\146\x3d\x22\x68\164\164\160\x3a\x2f\57\x70\x68\x70\x2e\156\145\164\57\155\x61\156\x75\141\154\x2f\145\x6e\57\x63\165\x72\x6c\56\151\x6e\x73\164\x61\154\154\x61\164\x69\157\156\56\x70\x68\x70\x22\x3e\x50\x48\x50\x20\x63\x55\x52\114\x20\x65\170\x74\145\156\163\x69\157\156\74\x2f\x61\x3e\x20\151\x73\x20\156\157\x74\x20\x69\156\x73\x74\x61\154\x6c\x65\144\40\x6f\162\x20\144\x69\163\x61\142\x6c\145\144\x2e"));
        SM:
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\x2f\155\157\x61\x73\x2f\162\145\163\x74\57\143\x75\x73\x74\x6f\155\x65\162\57\153\x65\x79";
        $yG = curl_init($zi);
        $ZK = $this->email;
        $ct = $this->password;
        $xE = array("\x65\x6d\141\x69\154" => $ZK, "\160\141\163\x73\167\157\162\144" => $ct);
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($yG, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\x6f\x6e\164\x65\x6e\164\55\124\171\x70\x65\x3a\x20\141\x70\x70\154\x69\143\141\x74\151\157\x6e\x2f\152\x73\157\x6e", "\x63\150\141\162\x73\145\164\72\40\x55\x54\106\x20\x2d\40\x38", "\101\165\164\150\x6f\x72\x69\x7a\141\164\151\x6f\156\x3a\x20\x42\x61\x73\151\x63"));
        curl_setopt($yG, CURLOPT_POST, TRUE);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto Jb;
        }
        $D6 = array("\45\155\145\x74\150\157\x64" => "\147\145\x74\103\x75\x73\164\157\155\x65\162\x4b\145\x79\x73", "\x25\146\151\154\x65" => "\143\165\x73\x74\x6f\x6d\x65\162\x5f\x73\145\x74\165\160\x2e\x70\150\160", "\45\145\162\x72\157\162" => curl_error($yG));
        watchdog("\x6d\151\156\x69\x6f\x72\x61\156\x67\x65\x5f\x73\x61\x6d\154\137\x69\x64\x70", "\105\162\162\157\x72\x20\141\x74\x20\x25\155\145\164\x68\157\x64\40\x6f\146\40\45\x66\151\154\145\x3a\40\x25\145\x72\x72\157\162", $D6);
        Jb:
        curl_close($yG);
        return $ES;
    }
    public function sendOtp()
    {
        if (IDPUtilities::isCurlInstalled()) {
            goto Fm;
        }
        return json_encode(array("\163\164\141\x74\x75\163" => "\x43\125\x52\114\x5f\x45\122\x52\x4f\122", "\x73\164\x61\164\x75\x73\x4d\145\x73\x73\141\147\x65" => "\x3c\x61\40\x68\x72\x65\146\x3d\x22\x68\x74\164\x70\x3a\57\57\x70\x68\160\56\156\x65\164\57\x6d\141\x6e\x75\x61\x6c\57\x65\156\x2f\143\x75\162\154\x2e\151\156\163\164\141\x6c\x6c\x61\x74\151\157\x6e\56\x70\x68\160\42\x3e\120\x48\x50\40\143\x55\122\x4c\40\x65\170\164\145\156\x73\151\x6f\156\x3c\x2f\x61\x3e\40\x69\x73\40\x6e\157\164\x20\151\x6e\x73\164\141\x6c\x6c\145\144\40\157\x72\x20\x64\151\x73\x61\x62\154\145\x64\x2e"));
        Fm:
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\57\x6d\157\141\163\x2f\x61\x70\x69\x2f\x61\165\164\x68\x2f\x63\x68\x61\x6c\154\145\156\147\145";
        $yG = curl_init($zi);
        $Fh = $this->defaultCustomerId;
        $sG = $this->defaultCustomerApiKey;
        $Zs = variable_get("\155\151\x6e\x69\x6f\162\x61\156\x67\145\x5f\x73\x61\155\x6c\137\x69\144\x70\137\x63\165\163\x74\x6f\155\145\162\x5f\141\144\x6d\151\156\x5f\145\x6d\141\151\x6c", NULL);
        $Zw = round(microtime(TRUE) * 1000);
        $pj = $Fh . number_format($vB, 0, '', '') . $sG;
        $di = hash("\163\x68\141\x35\61\62", $pj);
        $UW = "\103\x75\x73\164\157\x6d\145\x72\x2d\x4b\x65\x79\x3a\x20" . $Fh;
        $qj = "\x54\151\155\x65\163\164\141\x6d\160\72\x20" . number_format($vB, 0, '', '');
        $SX = "\x41\165\x74\x68\x6f\x72\151\x7a\141\164\x69\x6f\156\x3a\40" . $di;
        $xE = array("\143\x75\163\x74\x6f\x6d\145\x72\113\145\171" => $Fh, "\145\155\141\151\154" => $Zs, "\x61\x75\164\x68\x54\171\x70\145" => "\x45\115\x41\111\114");
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($yG, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\103\x6f\156\x74\x65\x6e\x74\55\124\x79\160\x65\72\x20\x61\x70\160\154\151\143\141\x74\151\x6f\x6e\57\152\163\157\156", $UW, $qj, $SX));
        curl_setopt($yG, CURLOPT_POST, TRUE);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto Jq;
        }
        $D6 = array("\x25\155\145\164\150\x6f\x64" => "\x73\x65\156\144\x4f\164\160", "\45\x66\151\x6c\x65" => "\x63\165\163\x74\x6f\x6d\x65\162\x5f\163\145\x74\x75\160\x2e\160\150\160", "\45\x65\162\x72\x6f\162" => curl_error($yG));
        watchdog("\x6d\151\156\151\x6f\x72\x61\x6e\147\x65\x5f\x73\141\x6d\x6c\137\x69\144\160", "\105\162\162\157\x72\x20\x61\x74\40\45\x6d\145\x74\x68\x6f\144\40\x6f\146\x20\x25\x66\151\154\x65\x3a\x20\45\x65\x72\162\157\x72", $D6);
        Jq:
        curl_close($yG);
        return $ES;
    }
    public function validateOtp($um)
    {
        if (IDPUtilities::isCurlInstalled()) {
            goto oh;
        }
        return json_encode(array("\x73\x74\x61\x74\165\x73" => "\103\x55\x52\x4c\137\x45\122\122\117\x52", "\163\164\141\x74\x75\x73\115\x65\163\163\141\147\145" => "\x3c\x61\x20\x68\x72\x65\146\x3d\42\150\164\164\160\x3a\57\x2f\x70\150\x70\56\156\x65\x74\x2f\155\x61\156\x75\x61\154\57\145\x6e\x2f\x63\165\x72\154\x2e\151\156\x73\164\x61\154\x6c\141\x74\151\x6f\x6e\x2e\x70\x68\x70\x22\x3e\x50\x48\120\x20\143\125\x52\x4c\x20\145\170\x74\145\x6e\163\x69\x6f\x6e\74\57\x61\x3e\40\x69\x73\40\156\x6f\x74\40\x69\x6e\x73\x74\x61\x6c\x6c\x65\144\x20\x6f\162\40\x64\x69\163\x61\142\x6c\145\144\56"));
        oh:
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\57\155\157\x61\x73\57\x61\x70\x69\57\141\165\164\x68\57\x76\x61\x6c\x69\x64\x61\164\145";
        $yG = curl_init($zi);
        $Fh = $this->defaultCustomerId;
        $sG = $this->defaultCustomerApiKey;
        $Zw = round(microtime(TRUE) * 1000);
        $pj = $Fh . number_format($vB, 0, '', '') . $sG;
        $di = hash("\x73\x68\x61\x35\61\62", $pj);
        $UW = "\103\x75\x73\164\x6f\x6d\145\x72\x2d\113\x65\171\72\40" . $Fh;
        $qj = "\x54\151\155\x65\163\164\141\155\160\x3a\x20" . number_format($vB, 0, '', '');
        $SX = "\101\165\164\150\x6f\x72\x69\x7a\141\164\x69\157\156\72\x20" . $di;
        $xE = array("\x74\x78\x49\x64" => $um, "\x74\157\153\145\x6e" => $this->otpToken);
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($yG, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\157\x6e\x74\145\156\164\x2d\124\171\x70\x65\72\40\141\x70\x70\154\151\x63\141\x74\x69\x6f\x6e\57\152\x73\157\156", $UW, $qj, $SX));
        curl_setopt($yG, CURLOPT_POST, TRUE);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto xU;
        }
        $D6 = array("\45\155\x65\164\150\x6f\144" => "\x76\x61\x6c\151\144\141\x74\145\117\x74\160", "\x25\146\x69\154\x65" => "\143\x75\x73\164\157\x6d\145\162\x5f\163\145\164\x75\160\56\160\x68\x70", "\x25\x65\162\162\x6f\162" => curl_error($yG));
        watchdog("\155\151\156\x69\x6f\162\141\x6e\147\145\137\x73\x61\x6d\154\137\x69\x64\x70", "\105\x72\x72\x6f\x72\40\x61\x74\40\45\x6d\145\164\150\157\144\x20\157\x66\x20\x25\146\151\x6c\x65\x3a\x20\x25\x65\x72\162\x6f\x72", $D6);
        xU:
        curl_close($yG);
        return $ES;
    }
    function check_status($rC)
    {
        global $base_url;
        if (IDPUtilities::isCurlInstalled()) {
            goto oL;
        }
        return json_encode(array("\163\x74\x61\164\165\x73" => "\x43\x55\x52\114\x5f\x45\x52\x52\117\x52", "\163\x74\141\x74\165\163\115\x65\x73\163\x61\147\145" => "\x3c\x61\40\150\x72\145\x66\75\x22\x68\x74\x74\x70\72\x2f\57\160\x68\160\56\156\x65\164\x2f\155\x61\156\165\141\154\57\145\x6e\x2f\x63\165\x72\x6c\56\x69\156\x73\x74\141\154\x6c\141\164\x69\157\156\56\x70\x68\160\x22\x3e\x50\110\120\40\143\x55\122\x4c\40\x65\x78\164\x65\x6e\x73\151\157\156\x3c\57\141\76\x20\x69\163\x20\x6e\x6f\164\40\151\x6e\x73\x74\x61\154\154\x65\x64\x20\x6f\x72\40\x64\151\163\x61\x62\x6c\x65\144\56"));
        oL:
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\x2f\x6d\x6f\141\163\x2f\x61\160\x69\x2f\142\x61\x63\x6b\x75\160\143\x6f\x64\x65\x2f\166\x65\x72\151\x66\x79";
        $yG = curl_init($zi);
        $Eb = variable_get("\155\151\156\x69\157\x72\141\x6e\x67\x65\137\163\x61\x6d\154\137\151\x64\160\137\143\x75\163\164\157\155\145\162\137\151\x64", '');
        $dY = variable_get("\x6d\x69\x6e\151\x6f\x72\141\156\x67\x65\x5f\163\x61\155\x6c\x5f\151\144\x70\x5f\143\x75\x73\x74\x6f\x6d\x65\162\137\x61\x70\x69\137\x6b\145\171", '');
        $vB = round(microtime(TRUE) * 1000);
        $kF = $Eb . number_format($vB, 0, '', '') . $dY;
        $qp = hash("\x73\x68\x61\65\x31\x32", $kF);
        $XY = "\x43\x75\x73\164\x6f\155\x65\x72\55\113\145\x79\x3a\40" . $Eb;
        $uW = "\124\x69\155\145\x73\164\x61\x6d\x70\x3a\40" . number_format($vB, 0, '', '');
        $bK = "\101\165\x74\x68\157\162\x69\x7a\x61\164\x69\157\x6e\x3a\x20" . $qp;
        $xE = '';
        $xE = array("\143\x6f\144\145" => $rC, "\x63\165\x73\164\x6f\x6d\145\162\x4b\145\x79" => $Eb, "\141\144\144\151\x74\x69\157\x6e\141\x6c\106\151\x65\154\x64\163" => array("\146\151\145\x6c\x64\x31" => $base_url));
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($yG, CURLOPT_AUTOREFERER, true);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\157\156\164\145\156\164\55\x54\171\160\145\72\x20\x61\x70\x70\154\151\x63\x61\x74\x69\157\x6e\57\152\163\157\156", $XY, $uW, $bK));
        curl_setopt($yG, CURLOPT_POST, true);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        curl_setopt($yG, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($yG, CURLOPT_TIMEOUT, 20);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto Om;
        }
        echo "\122\x65\x71\165\145\x73\x74\x20\105\162\162\x6f\162\72" . curl_error($yG);
        exit;
        Om:
        curl_close($yG);
        $ES = json_decode($ES, true);
        return $ES;
    }
    function ccl()
    {
        global $base_url;
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\x2f\x6d\x6f\141\x73\57\162\x65\163\164\57\x63\165\x73\x74\x6f\155\x65\162\x2f\154\151\143\145\156\163\145";
        $yG = curl_init($zi);
        $Eb = variable_get("\155\x69\156\151\x6f\162\141\x6e\147\x65\x5f\163\141\155\x6c\137\x69\144\160\x5f\143\x75\163\x74\157\155\145\x72\137\151\x64", '');
        $dY = variable_get("\x6d\x69\x6e\151\x6f\162\x61\x6e\147\x65\x5f\163\141\155\154\x5f\151\x64\x70\x5f\x63\165\x73\164\x6f\155\145\162\137\x61\160\x69\137\x6b\x65\x79", '');
        $vB = round(microtime(TRUE) * 1000);
        $kF = $Eb . number_format($vB, 0, '', '') . $dY;
        $qp = hash("\163\150\141\65\61\x32", $kF);
        $XY = "\x43\165\x73\164\157\155\145\162\55\x4b\145\x79\x3a\40" . $Eb;
        $uW = "\x54\151\x6d\x65\163\x74\x61\x6d\160\x3a\40" . number_format($vB, 0, '', '');
        $bK = "\101\x75\x74\x68\x6f\x72\151\172\x61\164\151\157\156\x3a\x20" . $qp;
        $xE = '';
        $xE = array("\143\165\163\x74\157\x6d\x65\162\111\x64" => $Eb, "\x61\x70\x70\x6c\151\x63\141\164\x69\157\156\116\x61\155\x65" => "\x64\x72\165\x70\x61\x6c\137\x73\141\x6d\x6c\137\x69\144\160");
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($yG, CURLOPT_AUTOREFERER, true);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\x6f\x6e\x74\x65\156\164\x2d\x54\171\160\x65\72\40\141\160\x70\x6c\151\143\x61\x74\151\x6f\x6e\57\152\x73\157\x6e", $XY, $uW, $bK));
        curl_setopt($yG, CURLOPT_POST, true);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        curl_setopt($yG, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($yG, CURLOPT_TIMEOUT, 20);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto RN;
        }
        return null;
        RN:
        curl_close($yG);
        return $ES;
    }
    function update_status()
    {
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\x2f\155\x6f\x61\163\x2f\141\160\151\57\142\141\143\153\x75\160\143\x6f\144\x65\x2f\165\160\144\x61\164\x65\x73\164\141\x74\x75\163";
        $yG = curl_init($zi);
        $Eb = variable_get("\x6d\x69\x6e\151\157\162\x61\x6e\147\x65\x5f\163\x61\155\154\137\151\x64\160\137\143\x75\x73\x74\x6f\x6d\145\x72\x5f\151\144", '');
        $dY = variable_get("\155\x69\156\x69\157\162\141\156\x67\145\137\x73\x61\155\154\137\151\144\160\x5f\x63\165\163\x74\157\155\x65\x72\x5f\x61\x70\x69\137\x6b\145\171", '');
        $BT = variable_get("\155\x69\x6e\151\157\162\x61\x6e\147\x65\x5f\163\141\x6d\x6c\137\x69\x64\160\137\x73\155\x6c\x5f\154\x6b", '');
        $vB = round(microtime(TRUE) * 1000);
        $kF = $Eb . number_format($vB, 0, '', '') . $dY;
        $qp = hash("\x73\150\141\x35\61\62", $kF);
        $XY = "\103\165\x73\x74\157\155\x65\162\x2d\113\x65\x79\x3a\40" . $Eb;
        $uW = "\x54\151\x6d\145\163\164\x61\x6d\160\x3a\40" . number_format($vB, 0, '', '');
        $bK = "\x41\x75\164\x68\157\x72\x69\x7a\141\164\151\157\x6e\72\x20" . $qp;
        $gH = variable_get("\155\x69\156\x69\x6f\162\141\x6e\x67\x65\x5f\x73\x61\155\x6c\137\x69\x64\160\137\x63\165\163\164\157\155\x65\x72\x5f\x61\x64\x6d\x69\156\x5f\x74\157\153\145\156", '');
        $rC = IDPUtilities::decrypt($BT, $gH);
        $xE = array("\x63\157\x64\145" => $rC, "\143\165\x73\164\x6f\155\145\x72\x4b\145\x79" => $Eb);
        $Ez = json_encode($xE);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($yG, CURLOPT_AUTOREFERER, true);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\157\x6e\x74\x65\x6e\x74\x2d\x54\171\x70\145\x3a\40\x61\160\160\154\151\x63\141\164\151\x6f\156\x2f\152\163\x6f\156", $XY, $uW, $bK));
        curl_setopt($yG, CURLOPT_POST, true);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        curl_setopt($yG, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($yG, CURLOPT_TIMEOUT, 20);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto AF;
        }
        echo "\x52\145\161\165\145\x73\164\x20\x45\x72\x72\x6f\x72\x3a" . curl_error($yG);
        exit;
        AF:
        curl_close($yG);
        return $ES;
    }
}
