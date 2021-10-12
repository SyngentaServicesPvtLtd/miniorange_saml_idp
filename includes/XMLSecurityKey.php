<?php


class XMLSecurityKey
{
    const TRIPLEDES_CBC = "\x68\x74\164\160\x3a\x2f\57\167\x77\167\x2e\x77\x33\x2e\157\x72\147\57\x32\x30\x30\61\57\x30\64\x2f\x78\155\x6c\x65\x6e\x63\x23\x74\x72\x69\x70\x6c\145\144\x65\163\x2d\x63\x62\x63";
    const AES128_CBC = "\150\164\x74\x70\x3a\x2f\x2f\x77\167\167\56\167\x33\56\157\x72\147\57\x32\60\60\61\57\60\64\x2f\170\x6d\x6c\145\156\143\43\x61\145\163\61\62\x38\x2d\x63\142\143";
    const AES192_CBC = "\x68\164\x74\160\72\x2f\x2f\167\x77\167\x2e\167\x33\x2e\x6f\x72\147\x2f\62\60\x30\x31\x2f\60\64\x2f\170\155\x6c\145\x6e\143\x23\141\x65\163\61\71\x32\x2d\143\x62\x63";
    const AES256_CBC = "\x68\x74\x74\x70\72\57\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\147\x2f\x32\60\60\x31\x2f\60\64\x2f\170\x6d\154\x65\x6e\143\43\x61\x65\163\x32\65\66\x2d\x63\142\x63";
    const RSA_1_5 = "\150\164\164\x70\72\57\x2f\167\167\x77\56\x77\x33\56\157\162\147\x2f\62\60\x30\61\57\60\64\57\x78\x6d\154\145\156\143\x23\x72\x73\141\x2d\x31\137\x35";
    const RSA_OAEP_MGF1P = "\x68\x74\164\x70\x3a\x2f\x2f\167\167\167\56\167\x33\56\x6f\162\x67\x2f\x32\60\60\x31\x2f\60\64\57\170\155\154\145\x6e\x63\43\162\163\x61\x2d\x6f\141\x65\x70\55\x6d\x67\146\61\160";
    const DSA_SHA1 = "\150\164\x74\160\x3a\x2f\x2f\167\167\x77\56\167\x33\x2e\x6f\162\x67\x2f\62\60\60\x30\57\x30\71\57\x78\155\x6c\x64\163\x69\x67\x23\x64\x73\141\55\x73\x68\x61\61";
    const RSA_SHA1 = "\150\164\164\160\x3a\57\57\x77\167\167\56\x77\x33\x2e\157\162\x67\57\x32\60\60\x30\57\60\71\57\170\155\154\x64\163\151\147\x23\x72\163\141\55\163\x68\141\61";
    const RSA_SHA256 = "\150\164\164\x70\x3a\57\x2f\167\x77\167\x2e\167\x33\x2e\157\162\x67\57\x32\60\x30\61\57\x30\64\57\170\x6d\154\x64\x73\151\x67\55\155\157\162\145\x23\162\163\x61\55\163\x68\141\x32\65\x36";
    const RSA_SHA384 = "\x68\164\164\x70\x3a\x2f\57\167\167\x77\x2e\x77\x33\56\157\x72\147\57\62\x30\x30\x31\57\60\x34\57\x78\x6d\x6c\x64\x73\x69\147\x2d\155\x6f\x72\145\x23\x72\x73\141\55\x73\150\141\x33\x38\64";
    const RSA_SHA512 = "\150\164\164\160\72\57\57\x77\x77\167\56\x77\63\56\x6f\162\147\57\62\x30\x30\61\57\x30\64\x2f\170\155\154\x64\x73\x69\147\x2d\x6d\157\162\x65\43\162\163\141\55\x73\x68\141\65\x31\x32";
    const HMAC_SHA1 = "\150\x74\x74\x70\72\57\57\x77\167\167\56\x77\63\56\157\162\147\57\62\x30\60\60\57\60\71\x2f\170\x6d\x6c\x64\x73\151\147\43\x68\x6d\x61\143\x2d\163\150\x61\61";
    private $cryptParams = array();
    public $type = 0;
    public $key = null;
    public $passphrase = '';
    public $iv = null;
    public $name = null;
    public $keyChain = null;
    public $isEncrypted = false;
    public $encryptedCtx = null;
    public $guid = null;
    private $x509Certificate = null;
    private $X509Thumbprint = null;
    public function __construct($i9, $A7 = null)
    {
        switch ($i9) {
            case self::TRIPLEDES_CBC:
                $this->cryptParams["\154\x69\142\x72\141\162\x79"] = "\157\160\145\x6e\x73\x73\154";
                $this->cryptParams["\x63\151\160\150\x65\x72"] = "\144\145\163\55\145\144\x65\x33\x2d\143\x62\143";
                $this->cryptParams["\164\171\x70\145"] = "\x73\x79\155\x6d\145\164\162\151\x63";
                $this->cryptParams["\155\x65\164\150\157\144"] = "\x68\164\164\160\72\57\x2f\x77\x77\x77\x2e\x77\x33\x2e\157\x72\x67\57\62\60\60\x31\x2f\x30\x34\57\x78\155\x6c\x65\x6e\x63\x23\x74\162\151\160\154\x65\144\x65\x73\55\x63\x62\143";
                $this->cryptParams["\x6b\145\171\163\151\172\x65"] = 24;
                $this->cryptParams["\142\x6c\x6f\143\153\163\x69\x7a\145"] = 8;
                goto Nt;
            case self::AES128_CBC:
                $this->cryptParams["\x6c\x69\142\162\x61\x72\x79"] = "\157\160\x65\x6e\163\163\154";
                $this->cryptParams["\x63\x69\160\x68\145\x72"] = "\x61\145\x73\55\61\x32\x38\x2d\143\x62\143";
                $this->cryptParams["\164\x79\x70\145"] = "\x73\171\x6d\x6d\x65\164\162\151\143";
                $this->cryptParams["\x6d\x65\x74\150\x6f\x64"] = "\150\164\164\x70\x3a\57\x2f\x77\x77\167\56\x77\63\x2e\157\x72\x67\57\62\60\60\61\x2f\60\64\57\x78\x6d\x6c\x65\156\143\43\141\145\163\x31\x32\x38\x2d\x63\x62\x63";
                $this->cryptParams["\x6b\x65\171\x73\151\172\x65"] = 16;
                $this->cryptParams["\142\x6c\x6f\143\x6b\163\151\x7a\x65"] = 16;
                goto Nt;
            case self::AES192_CBC:
                $this->cryptParams["\x6c\151\142\x72\x61\162\171"] = "\x6f\x70\145\x6e\x73\163\154";
                $this->cryptParams["\x63\151\x70\x68\x65\x72"] = "\x61\x65\x73\x2d\61\x39\62\x2d\x63\x62\x63";
                $this->cryptParams["\164\171\x70\x65"] = "\x73\171\x6d\x6d\x65\164\x72\151\143";
                $this->cryptParams["\x6d\145\x74\x68\157\144"] = "\150\x74\x74\160\72\57\57\167\167\167\x2e\167\63\56\157\162\x67\x2f\62\60\x30\61\57\60\x34\x2f\x78\155\154\145\x6e\143\x23\x61\x65\x73\61\x39\62\x2d\143\142\143";
                $this->cryptParams["\153\145\x79\x73\x69\x7a\x65"] = 24;
                $this->cryptParams["\142\154\157\143\153\x73\x69\x7a\145"] = 16;
                goto Nt;
            case self::AES256_CBC:
                $this->cryptParams["\x6c\151\142\162\141\162\171"] = "\x6f\x70\145\156\x73\163\x6c";
                $this->cryptParams["\143\151\x70\x68\x65\162"] = "\x61\145\x73\x2d\62\65\x36\55\x63\x62\x63";
                $this->cryptParams["\164\x79\x70\145"] = "\163\171\155\x6d\x65\164\162\x69\143";
                $this->cryptParams["\155\x65\x74\150\x6f\144"] = "\x68\164\x74\x70\x3a\x2f\x2f\x77\x77\167\x2e\x77\63\x2e\x6f\x72\x67\57\62\60\60\x31\57\60\64\57\x78\x6d\154\145\156\143\x23\141\x65\x73\x32\x35\x36\x2d\x63\142\x63";
                $this->cryptParams["\x6b\145\171\163\x69\x7a\x65"] = 32;
                $this->cryptParams["\x62\x6c\157\143\x6b\163\151\x7a\145"] = 16;
                goto Nt;
            case self::RSA_1_5:
                $this->cryptParams["\154\x69\x62\x72\x61\x72\x79"] = "\157\x70\x65\x6e\x73\x73\x6c";
                $this->cryptParams["\x70\141\144\144\151\x6e\x67"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\x6d\145\x74\150\157\144"] = "\x68\x74\164\160\x3a\x2f\x2f\x77\167\x77\56\x77\x33\x2e\x6f\x72\147\x2f\62\x30\x30\61\x2f\x30\x34\x2f\x78\x6d\x6c\x65\x6e\143\43\162\x73\141\55\x31\x5f\65";
                if (!(is_array($A7) && !empty($A7["\x74\x79\x70\145"]))) {
                    goto tv;
                }
                if (!($A7["\x74\171\160\x65"] == "\x70\x75\x62\x6c\x69\143" || $A7["\164\x79\x70\145"] == "\x70\x72\151\166\141\164\145")) {
                    goto nO;
                }
                $this->cryptParams["\164\x79\x70\145"] = $A7["\x74\x79\x70\x65"];
                goto Nt;
                nO:
                tv:
                throw new Exception("\103\x65\162\164\x69\146\151\x63\141\x74\x65\40\42\164\171\160\x65\x22\40\50\x70\162\x69\x76\141\164\145\57\x70\x75\142\x6c\151\x63\x29\x20\155\165\163\x74\40\142\145\40\x70\141\163\163\x65\x64\40\x76\151\141\x20\160\141\x72\x61\155\x65\x74\145\x72\x73");
            case self::RSA_OAEP_MGF1P:
                $this->cryptParams["\154\x69\142\162\x61\162\x79"] = "\157\x70\145\156\x73\x73\154";
                $this->cryptParams["\x70\x61\144\144\151\156\x67"] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->cryptParams["\155\145\164\150\157\x64"] = "\x68\x74\x74\160\72\x2f\57\167\x77\167\56\x77\x33\x2e\x6f\x72\147\57\x32\60\x30\61\x2f\x30\x34\x2f\170\x6d\154\145\156\x63\43\x72\x73\x61\55\157\x61\145\160\55\x6d\147\146\61\x70";
                $this->cryptParams["\x68\141\163\150"] = null;
                if (!(is_array($A7) && !empty($A7["\x74\171\160\145"]))) {
                    goto XN;
                }
                if (!($A7["\x74\x79\160\145"] == "\160\x75\142\154\151\x63" || $A7["\164\x79\160\145"] == "\x70\x72\x69\x76\141\164\x65")) {
                    goto j1;
                }
                $this->cryptParams["\x74\x79\160\x65"] = $A7["\164\x79\160\145"];
                goto Nt;
                j1:
                XN:
                throw new Exception("\x43\x65\x72\x74\x69\x66\151\x63\x61\x74\145\x20\42\x74\171\x70\x65\42\x20\50\160\162\x69\x76\141\x74\145\57\x70\x75\x62\154\x69\143\x29\40\x6d\165\163\164\x20\142\145\x20\x70\x61\163\163\x65\x64\40\166\151\141\40\x70\x61\162\x61\x6d\145\164\145\x72\x73");
            case self::RSA_SHA1:
                $this->cryptParams["\x6c\151\142\162\141\x72\x79"] = "\157\x70\145\x6e\x73\x73\x6c";
                $this->cryptParams["\155\x65\x74\150\157\144"] = "\x68\x74\x74\x70\72\57\57\167\167\167\x2e\x77\63\x2e\x6f\x72\147\57\x32\60\x30\x30\57\x30\x39\x2f\170\155\154\144\163\151\x67\43\162\163\141\55\x73\x68\141\61";
                $this->cryptParams["\x70\141\144\x64\151\156\x67"] = OPENSSL_PKCS1_PADDING;
                if (!(is_array($A7) && !empty($A7["\x74\171\x70\x65"]))) {
                    goto Dv;
                }
                if (!($A7["\164\x79\x70\145"] == "\x70\165\x62\x6c\x69\143" || $A7["\x74\x79\x70\x65"] == "\160\162\151\x76\141\164\x65")) {
                    goto cy;
                }
                $this->cryptParams["\164\x79\160\x65"] = $A7["\x74\171\x70\145"];
                goto Nt;
                cy:
                Dv:
                throw new Exception("\103\145\162\x74\151\x66\151\x63\141\x74\x65\40\x22\164\x79\x70\x65\x22\40\50\x70\162\x69\166\x61\x74\145\57\160\x75\142\154\151\143\51\40\x6d\165\163\164\x20\142\x65\40\160\x61\x73\x73\x65\144\40\166\x69\x61\x20\160\x61\x72\x61\155\x65\164\145\x72\x73");
            case self::RSA_SHA256:
                $this->cryptParams["\x6c\x69\142\x72\141\x72\x79"] = "\x6f\x70\145\x6e\x73\163\154";
                $this->cryptParams["\x6d\x65\164\150\x6f\x64"] = "\x68\164\164\160\72\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\147\x2f\x32\x30\x30\x31\x2f\60\x34\57\170\155\x6c\144\x73\x69\147\x2d\x6d\x6f\x72\145\x23\162\x73\x61\55\163\x68\x61\x32\x35\x36";
                $this->cryptParams["\x70\141\x64\x64\151\x6e\x67"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\x69\x67\145\x73\x74"] = "\123\110\x41\x32\x35\x36";
                if (!(is_array($A7) && !empty($A7["\x74\x79\160\x65"]))) {
                    goto uq;
                }
                if (!($A7["\x74\171\160\145"] == "\x70\165\142\x6c\x69\143" || $A7["\x74\x79\160\x65"] == "\x70\162\x69\x76\141\164\x65")) {
                    goto OL;
                }
                $this->cryptParams["\164\x79\160\145"] = $A7["\x74\x79\160\145"];
                goto Nt;
                OL:
                uq:
                throw new Exception("\x43\x65\x72\164\x69\146\x69\x63\x61\x74\x65\x20\x22\164\171\160\x65\x22\x20\50\160\x72\x69\166\x61\164\145\x2f\x70\x75\x62\154\151\143\51\x20\155\165\x73\164\40\x62\x65\40\x70\141\163\163\x65\144\40\x76\x69\141\40\160\x61\x72\141\155\x65\x74\x65\162\x73");
            case self::RSA_SHA384:
                $this->cryptParams["\154\151\x62\162\x61\x72\171"] = "\157\x70\145\156\163\163\154";
                $this->cryptParams["\155\145\x74\x68\x6f\144"] = "\150\164\x74\x70\x3a\x2f\57\x77\x77\167\x2e\167\x33\56\157\162\147\x2f\x32\60\x30\x31\57\60\64\57\170\x6d\x6c\x64\x73\151\147\x2d\155\x6f\162\145\x23\x72\x73\x61\x2d\x73\x68\x61\x33\x38\x34";
                $this->cryptParams["\x70\141\x64\144\151\x6e\x67"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\x69\147\x65\x73\x74"] = "\x53\110\101\x33\70\x34";
                if (!(is_array($A7) && !empty($A7["\x74\171\x70\145"]))) {
                    goto cC;
                }
                if (!($A7["\164\x79\160\145"] == "\160\165\142\154\x69\x63" || $A7["\x74\x79\x70\145"] == "\x70\x72\151\x76\x61\x74\145")) {
                    goto N0;
                }
                $this->cryptParams["\164\x79\x70\145"] = $A7["\x74\x79\160\x65"];
                goto Nt;
                N0:
                cC:
                throw new Exception("\x43\x65\x72\x74\x69\146\x69\x63\x61\164\145\x20\42\x74\171\x70\x65\42\x20\x28\160\162\151\166\x61\164\x65\57\160\x75\x62\x6c\151\x63\x29\x20\155\165\163\164\x20\142\x65\40\160\141\x73\x73\145\x64\40\x76\151\141\40\160\x61\x72\141\x6d\x65\x74\145\x72\x73");
            case self::RSA_SHA512:
                $this->cryptParams["\154\151\142\x72\x61\x72\171"] = "\x6f\160\x65\x6e\x73\x73\154";
                $this->cryptParams["\x6d\145\x74\x68\157\144"] = "\x68\x74\164\x70\72\57\x2f\x77\x77\167\56\x77\63\x2e\157\x72\x67\57\62\x30\x30\61\57\60\64\x2f\x78\155\154\x64\163\151\147\x2d\x6d\x6f\x72\x65\43\162\x73\x61\55\163\150\x61\65\61\x32";
                $this->cryptParams["\x70\141\144\x64\151\156\x67"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\151\147\145\163\164"] = "\123\110\x41\65\61\x32";
                if (!(is_array($A7) && !empty($A7["\164\171\x70\145"]))) {
                    goto pX;
                }
                if (!($A7["\164\x79\x70\145"] == "\160\x75\x62\154\151\143" || $A7["\164\x79\160\145"] == "\x70\x72\x69\166\141\164\x65")) {
                    goto e8;
                }
                $this->cryptParams["\x74\x79\160\x65"] = $A7["\x74\171\160\x65"];
                goto Nt;
                e8:
                pX:
                throw new Exception("\x43\145\162\164\151\x66\151\143\141\x74\x65\x20\42\x74\171\160\145\42\x20\x28\x70\x72\151\166\141\x74\145\x2f\160\x75\x62\154\151\143\51\x20\x6d\x75\163\164\x20\x62\x65\40\160\141\163\x73\x65\x64\x20\166\x69\141\x20\160\x61\162\141\x6d\145\x74\x65\162\163");
            case self::HMAC_SHA1:
                $this->cryptParams["\154\151\x62\x72\x61\162\171"] = $i9;
                $this->cryptParams["\155\x65\x74\150\x6f\x64"] = "\x68\164\x74\x70\72\x2f\57\x77\167\x77\56\x77\x33\x2e\157\162\147\57\62\x30\60\x30\x2f\60\x39\x2f\x78\x6d\154\x64\163\x69\147\43\x68\x6d\141\x63\x2d\x73\x68\141\61";
                goto Nt;
            default:
                throw new Exception("\111\x6e\166\141\x6c\x69\x64\40\x4b\x65\171\x20\124\x79\x70\145");
        }
        Jy:
        Nt:
        $this->type = $i9;
    }
    public function getSymmetricKeySize()
    {
        if (isset($this->cryptParams["\153\145\x79\163\151\172\145"])) {
            goto Ro;
        }
        return null;
        Ro:
        return $this->cryptParams["\x6b\x65\171\x73\151\172\145"];
    }
    public function generateSessionKey()
    {
        if (isset($this->cryptParams["\x6b\x65\x79\x73\x69\172\145"])) {
            goto VQ;
        }
        throw new Exception("\125\x6e\x6b\156\157\167\x6e\40\x6b\x65\171\40\x73\151\172\x65\40\x66\157\162\40\164\171\x70\145\x20\42" . $this->type . "\42\x2e");
        VQ:
        $Bc = $this->cryptParams["\153\145\171\163\x69\x7a\145"];
        $gH = openssl_random_pseudo_bytes($Bc);
        if (!($this->type === self::TRIPLEDES_CBC)) {
            goto qK;
        }
        $c0 = 0;
        ZP:
        if (!($c0 < strlen($gH))) {
            goto Dq;
        }
        $AP = ord($gH[$c0]) & 0xfe;
        $s3 = 1;
        $jy = 1;
        dm:
        if (!($jy < 8)) {
            goto Kn;
        }
        $s3 ^= $AP >> $jy & 1;
        Hy:
        $jy++;
        goto dm;
        Kn:
        $AP |= $s3;
        $gH[$c0] = chr($AP);
        wu:
        $c0++;
        goto ZP;
        Dq:
        qK:
        $this->key = $gH;
        return $gH;
    }
    public static function getRawThumbprint($U2)
    {
        $EH = explode("\xa", $U2);
        $qB = '';
        $Bu = false;
        foreach ($EH as $qU) {
            if (!$Bu) {
                goto om;
            }
            if (!(strncmp($qU, "\x2d\x2d\55\55\55\x45\x4e\x44\40\x43\105\x52\124\111\106\x49\103\101\x54\105", 20) == 0)) {
                goto Ie;
            }
            goto Nz;
            Ie:
            $qB .= trim($qU);
            goto qO;
            om:
            if (!(strncmp($qU, "\55\x2d\55\55\55\102\105\107\x49\x4e\40\103\x45\x52\x54\111\x46\111\103\x41\124\105", 22) == 0)) {
                goto XT;
            }
            $Bu = true;
            XT:
            qO:
            kB:
        }
        Nz:
        if (empty($qB)) {
            goto zy;
        }
        return strtolower(sha1(base64_decode($qB)));
        zy:
        return null;
    }
    public function loadKey($gH, $d9 = false, $W_ = false)
    {
        if ($d9) {
            goto Oz;
        }
        $this->key = $gH;
        goto Bv;
        Oz:
        $this->key = file_get_contents($gH);
        Bv:
        if ($W_) {
            goto v7;
        }
        $this->x509Certificate = null;
        goto Sh;
        v7:
        $this->key = openssl_x509_read($this->key);
        openssl_x509_export($this->key, $P_);
        $this->x509Certificate = $P_;
        $this->key = $P_;
        Sh:
        if (!($this->cryptParams["\154\151\142\162\141\162\x79"] == "\x6f\x70\145\156\x73\x73\x6c")) {
            goto dn;
        }
        switch ($this->cryptParams["\x74\171\160\x65"]) {
            case "\160\165\142\154\151\x63":
                if (!$W_) {
                    goto Hq;
                }
                $this->X509Thumbprint = self::getRawThumbprint($this->key);
                Hq:
                $this->key = openssl_get_publickey($this->key);
                if ($this->key) {
                    goto J4;
                }
                throw new Exception("\125\x6e\x61\x62\x6c\145\x20\x74\x6f\40\x65\x78\164\x72\141\x63\164\40\x70\x75\x62\x6c\x69\x63\40\153\x65\171");
                J4:
                goto qI;
            case "\x70\162\151\x76\x61\x74\x65":
                $this->key = openssl_get_privatekey($this->key, $this->passphrase);
                goto qI;
            case "\x73\171\155\155\145\x74\162\151\143":
                if (!(strlen($this->key) < $this->cryptParams["\153\x65\x79\x73\151\x7a\145"])) {
                    goto n7;
                }
                throw new Exception("\113\x65\171\x20\155\x75\x73\x74\40\x63\157\156\164\x61\151\x6e\x20\x61\x74\40\x6c\145\x61\163\164\40\62\x35\40\x63\150\141\162\141\x63\164\x65\162\163\x20\x66\157\162\40\x74\x68\151\163\x20\x63\x69\x70\150\145\x72");
                n7:
                goto qI;
            default:
                throw new Exception("\x55\x6e\153\x6e\x6f\x77\x6e\x20\164\x79\x70\x65");
        }
        EC:
        qI:
        dn:
    }
    private function padISO10126($qB, $WW)
    {
        if (!($WW > 256)) {
            goto N1;
        }
        throw new Exception("\102\x6c\x6f\143\x6b\x20\x73\x69\x7a\145\x20\150\x69\x67\x68\145\x72\x20\x74\x68\141\156\x20\62\x35\x36\x20\x6e\157\164\x20\141\x6c\x6c\157\x77\x65\144");
        N1:
        $Sq = $WW - strlen($qB) % $WW;
        $jp = chr($Sq);
        return $qB . str_repeat($jp, $Sq);
    }
    private function unpadISO10126($qB)
    {
        $Sq = substr($qB, -1);
        $iV = ord($Sq);
        return substr($qB, 0, -$iV);
    }
    private function encryptSymmetric($qB)
    {
        $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cryptParams["\143\151\x70\x68\145\x72"]));
        $qB = $this->padISO10126($qB, $this->cryptParams["\142\x6c\x6f\143\x6b\x73\151\x7a\145"]);
        $wj = openssl_encrypt($qB, $this->cryptParams["\143\151\x70\x68\x65\162"], $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        if (!(false === $wj)) {
            goto Bs;
        }
        throw new Exception("\x46\x61\151\154\x75\162\145\x20\x65\156\x63\162\x79\x70\x74\151\156\x67\x20\104\141\x74\x61\40\x28\157\160\145\x6e\x73\x73\x6c\40\163\x79\x6d\x6d\x65\164\x72\151\x63\51\x20\55\40" . openssl_error_string());
        Bs:
        return $this->iv . $wj;
    }
    private function decryptSymmetric($qB)
    {
        $xX = openssl_cipher_iv_length($this->cryptParams["\143\151\x70\150\145\x72"]);
        $this->iv = substr($qB, 0, $xX);
        $qB = substr($qB, $xX);
        $xJ = openssl_decrypt($qB, $this->cryptParams["\x63\151\160\x68\145\x72"], $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        if (!(false === $xJ)) {
            goto pm;
        }
        throw new Exception("\106\141\151\154\x75\x72\145\40\144\x65\143\162\x79\x70\164\151\156\147\x20\x44\x61\x74\141\x20\x28\x6f\x70\145\x6e\x73\163\154\x20\x73\x79\155\155\x65\164\162\x69\143\x29\x20\x2d\40" . openssl_error_string());
        pm:
        return $this->unpadISO10126($xJ);
    }
    private function encryptPublic($qB)
    {
        if (openssl_public_encrypt($qB, $wj, $this->key, $this->cryptParams["\x70\x61\144\144\x69\x6e\147"])) {
            goto kO;
        }
        throw new Exception("\x46\x61\151\154\x75\162\145\40\x65\156\x63\x72\x79\160\164\151\x6e\147\x20\104\141\x74\x61\x20\x28\157\x70\145\156\x73\163\154\40\160\165\x62\x6c\x69\143\x29\x20\55\40" . openssl_error_string());
        kO:
        return $wj;
    }
    private function decryptPublic($qB)
    {
        if (openssl_public_decrypt($qB, $xJ, $this->key, $this->cryptParams["\x70\141\x64\x64\x69\156\147"])) {
            goto U8;
        }
        throw new Exception("\x46\x61\151\x6c\x75\x72\145\x20\144\145\143\162\x79\160\164\151\156\147\40\x44\141\x74\x61\x20\50\x6f\160\x65\156\163\163\x6c\40\x70\x75\x62\154\151\x63\51\40\x2d\x20" . openssl_error_string);
        U8:
        return $xJ;
    }
    private function encryptPrivate($qB)
    {
        if (openssl_private_encrypt($qB, $wj, $this->key, $this->cryptParams["\160\141\x64\144\151\156\147"])) {
            goto hu;
        }
        throw new Exception("\106\141\x69\x6c\x75\x72\x65\40\x65\156\x63\x72\x79\x70\164\151\156\x67\40\x44\x61\x74\141\x20\x28\157\x70\x65\156\x73\x73\x6c\40\160\x72\x69\x76\x61\164\145\51\x20\x2d\40" . openssl_error_string());
        hu:
        return $wj;
    }
    private function decryptPrivate($qB)
    {
        if (openssl_private_decrypt($qB, $xJ, $this->key, $this->cryptParams["\x70\141\x64\x64\151\x6e\x67"])) {
            goto qU;
        }
        throw new Exception("\x46\x61\x69\154\165\162\x65\x20\144\x65\x63\x72\x79\x70\164\x69\x6e\x67\40\x44\141\x74\x61\40\50\157\x70\145\156\163\163\x6c\x20\x70\162\151\166\141\x74\145\51\x20\55\40" . openssl_error_string);
        qU:
        return $xJ;
    }
    private function signOpenSSL($qB)
    {
        $IV = OPENSSL_ALGO_SHA1;
        if (empty($this->cryptParams["\x64\x69\147\x65\163\x74"])) {
            goto Fv;
        }
        $IV = $this->cryptParams["\144\x69\x67\145\x73\164"];
        Fv:
        if (openssl_sign($qB, $e0, $this->key, $IV)) {
            goto TF;
        }
        throw new Exception("\106\x61\151\x6c\165\162\145\40\x53\x69\147\156\x69\x6e\147\x20\104\141\164\141\x3a\40" . openssl_error_string() . "\x20\55\40" . $IV);
        TF:
        return $e0;
    }
    private function verifyOpenSSL($qB, $e0)
    {
        $IV = OPENSSL_ALGO_SHA1;
        if (empty($this->cryptParams["\x64\151\147\145\163\164"])) {
            goto Wp;
        }
        $IV = $this->cryptParams["\x64\151\147\145\x73\164"];
        Wp:
        return openssl_verify($qB, $e0, $this->key, $IV);
    }
    public function encryptData($qB)
    {
        if (!($this->cryptParams["\x6c\151\x62\x72\x61\x72\171"] === "\x6f\x70\x65\156\163\x73\154")) {
            goto mt;
        }
        switch ($this->cryptParams["\164\x79\160\x65"]) {
            case "\163\171\155\155\145\x74\x72\151\x63":
                return $this->encryptSymmetric($qB);
            case "\160\x75\x62\x6c\x69\x63":
                return $this->encryptPublic($qB);
            case "\160\x72\x69\166\141\164\145":
                return $this->encryptPrivate($qB);
        }
        bx:
        II:
        mt:
    }
    public function decryptData($qB)
    {
        if (!($this->cryptParams["\154\151\x62\162\x61\162\x79"] === "\x6f\x70\145\x6e\x73\163\x6c")) {
            goto Pn;
        }
        switch ($this->cryptParams["\x74\x79\x70\145"]) {
            case "\x73\x79\155\155\x65\x74\x72\151\143":
                return $this->decryptSymmetric($qB);
            case "\x70\x75\142\x6c\151\143":
                return $this->decryptPublic($qB);
            case "\x70\x72\x69\166\x61\x74\x65":
                return $this->decryptPrivate($qB);
        }
        ly:
        US:
        Pn:
    }
    public function signData($qB)
    {
        switch ($this->cryptParams["\x6c\151\x62\162\141\x72\x79"]) {
            case "\x6f\x70\145\156\x73\163\x6c":
                return $this->signOpenSSL($qB);
            case self::HMAC_SHA1:
                return hash_hmac("\x73\150\141\x31", $qB, $this->key, true);
        }
        ae:
        YU:
    }
    public function verifySignature($qB, $e0)
    {
        switch ($this->cryptParams["\154\x69\x62\x72\141\162\171"]) {
            case "\157\x70\145\x6e\163\163\154":
                return $this->verifyOpenSSL($qB, $e0);
            case self::HMAC_SHA1:
                $de = hash_hmac("\163\150\141\61", $qB, $this->key, true);
                return strcmp($e0, $de) == 0;
        }
        uG:
        q1:
    }
    public function getAlgorithm()
    {
        return $this->cryptParams["\155\145\x74\x68\157\144"];
    }
    public static function makeAsnSegment($i9, $Mk)
    {
        switch ($i9) {
            case 0x2:
                if (!(ord($Mk) > 0x7f)) {
                    goto za;
                }
                $Mk = chr(0) . $Mk;
                za:
                goto cx;
            case 0x3:
                $Mk = chr(0) . $Mk;
                goto cx;
        }
        Sn:
        cx:
        $kA = strlen($Mk);
        if ($kA < 128) {
            goto cm;
        }
        if ($kA < 0x100) {
            goto zW;
        }
        if ($kA < 0x10000) {
            goto Tg;
        }
        $AR = null;
        goto rd;
        Tg:
        $AR = sprintf("\45\143\45\143\x25\x63\x25\x63\x25\x73", $i9, 0x82, $kA / 0x100, $kA % 0x100, $Mk);
        rd:
        goto xL;
        zW:
        $AR = sprintf("\45\143\45\x63\x25\143\45\163", $i9, 0x81, $kA, $Mk);
        xL:
        goto I6;
        cm:
        $AR = sprintf("\45\143\x25\143\x25\163", $i9, $kA, $Mk);
        I6:
        return $AR;
    }
    public static function convertRSA($VS, $ZT)
    {
        $Il = self::makeAsnSegment(0x2, $ZT);
        $Fx = self::makeAsnSegment(0x2, $VS);
        $XB = self::makeAsnSegment(0x30, $Fx . $Il);
        $b6 = self::makeAsnSegment(0x3, $XB);
        $Nw = pack("\110\52", "\x33\x30\x30\x44\x30\66\x30\71\62\101\x38\x36\64\70\x38\x36\106\67\x30\104\x30\61\60\61\x30\61\60\x35\60\x30");
        $kL = self::makeAsnSegment(0x30, $Nw . $b6);
        $H5 = base64_encode($kL);
        $kC = "\x2d\x2d\55\x2d\55\102\105\x47\x49\116\x20\120\125\102\x4c\111\x43\40\x4b\105\131\55\55\55\x2d\x2d\12";
        $pg = 0;
        pR:
        if (!($QW = substr($H5, $pg, 64))) {
            goto Yl;
        }
        $kC = $kC . $QW . "\12";
        $pg += 64;
        goto pR;
        Yl:
        return $kC . "\x2d\x2d\x2d\x2d\55\x45\116\104\x20\x50\125\x42\x4c\111\103\x20\x4b\105\x59\55\55\x2d\x2d\55\xa";
    }
    public function getX509Certificate()
    {
        return $this->x509Certificate;
    }
    public function getX509Thumbprint()
    {
        return $this->X509Thumbprint;
    }
    public static function fromEncryptedKeyElement(DOMElement $h0)
    {
        $r0 = new XMLSecEnc();
        $r0->setNode($h0);
        if ($qX = $r0->locateKey()) {
            goto c1;
        }
        throw new Exception("\x55\x6e\x61\142\154\x65\40\x74\157\40\154\157\x63\x61\x74\x65\x20\x61\154\147\157\162\151\x74\x68\155\x20\x66\x6f\x72\40\x74\x68\x69\163\x20\105\x6e\x63\162\x79\x70\x74\x65\x64\x20\x4b\145\x79");
        c1:
        $qX->isEncrypted = true;
        $qX->encryptedCtx = $r0;
        XMLSecEnc::staticLocateKeyInfo($qX, $h0);
        return $qX;
    }
}
class XMLSecurityDSig
{
    const XMLDSIGNS = "\150\164\164\160\x3a\x2f\57\167\167\167\x2e\x77\x33\x2e\x6f\162\147\x2f\62\60\60\60\57\x30\71\x2f\x78\155\x6c\x64\163\x69\147\43";
    const SHA1 = "\150\164\x74\160\72\x2f\57\x77\167\167\x2e\x77\x33\x2e\157\x72\x67\x2f\x32\x30\60\x30\x2f\x30\x39\x2f\x78\x6d\154\144\163\151\147\43\x73\150\141\61";
    const SHA256 = "\150\x74\164\160\x3a\x2f\57\x77\x77\167\56\167\x33\56\x6f\x72\147\57\62\60\x30\x31\57\x30\64\x2f\170\x6d\154\145\x6e\143\43\163\x68\x61\62\x35\66";
    const SHA384 = "\150\x74\164\160\x3a\x2f\x2f\x77\167\167\56\167\x33\56\x6f\x72\147\x2f\62\x30\x30\61\57\x30\64\57\170\155\154\x64\163\x69\x67\x2d\x6d\x6f\162\145\43\x73\150\141\63\70\64";
    const SHA512 = "\x68\164\164\160\x3a\x2f\x2f\x77\167\x77\56\167\63\56\157\x72\147\57\x32\x30\60\x31\57\60\64\x2f\170\155\154\145\156\x63\x23\x73\x68\141\65\x31\x32";
    const RIPEMD160 = "\x68\x74\x74\x70\x3a\57\x2f\x77\x77\167\x2e\x77\63\56\157\162\147\57\x32\60\x30\61\57\x30\x34\x2f\170\x6d\154\x65\x6e\x63\43\162\x69\x70\145\x6d\144\x31\x36\60";
    const C14N = "\x68\164\164\x70\72\x2f\x2f\x77\167\x77\x2e\167\x33\56\x6f\162\147\57\124\x52\x2f\62\x30\60\61\57\122\x45\103\55\170\x6d\154\55\143\61\64\156\55\62\x30\60\61\x30\x33\61\x35";
    const C14N_COMMENTS = "\x68\x74\164\x70\x3a\x2f\x2f\x77\x77\167\56\167\63\56\x6f\x72\147\x2f\124\x52\x2f\x32\60\x30\x31\x2f\x52\105\103\x2d\170\155\x6c\55\x63\61\64\156\55\x32\60\x30\61\x30\63\61\65\43\127\151\164\x68\103\157\x6d\155\145\x6e\x74\x73";
    const EXC_C14N = "\150\x74\x74\x70\72\x2f\x2f\167\167\x77\x2e\167\x33\x2e\x6f\162\x67\57\x32\x30\x30\61\57\x31\x30\x2f\170\x6d\154\55\x65\170\x63\x2d\x63\61\64\x6e\43";
    const EXC_C14N_COMMENTS = "\x68\164\164\160\72\57\x2f\167\x77\x77\x2e\167\63\56\x6f\x72\x67\x2f\62\60\x30\x31\x2f\x31\x30\57\170\x6d\x6c\x2d\145\x78\x63\55\x63\x31\64\156\x23\127\151\x74\x68\x43\157\155\x6d\x65\156\x74\163";
    const template = "\74\144\x73\x3a\123\x69\147\x6e\141\x74\x75\x72\x65\x20\x78\x6d\154\x6e\163\72\144\x73\x3d\x22\x68\164\x74\160\x3a\x2f\x2f\x77\x77\x77\56\x77\x33\56\x6f\162\147\57\x32\x30\x30\x30\57\60\x39\57\170\155\x6c\144\x73\x69\147\43\x22\x3e\15\xa\x20\x20\74\144\x73\x3a\123\151\x67\x6e\145\x64\x49\x6e\x66\157\76\xd\xa\x20\40\40\40\x3c\x64\x73\x3a\x53\151\x67\x6e\x61\x74\165\162\x65\115\145\164\150\157\144\40\57\x3e\xd\12\40\40\x3c\x2f\x64\163\x3a\x53\151\147\x6e\145\x64\x49\156\146\157\x3e\15\12\x3c\x2f\144\x73\72\123\151\147\156\x61\x74\x75\x72\x65\x3e";
    const BASE_TEMPLATE = "\x3c\123\151\x67\156\x61\164\x75\x72\145\x20\x78\155\154\x6e\x73\75\x22\x68\x74\164\160\x3a\x2f\x2f\167\x77\x77\x2e\167\x33\56\x6f\162\x67\57\62\x30\x30\60\x2f\x30\71\57\x78\x6d\x6c\x64\x73\x69\147\x23\42\x3e\15\12\x20\40\74\123\151\x67\x6e\x65\x64\111\156\146\x6f\76\xd\xa\40\40\x20\40\x3c\123\151\147\156\x61\x74\x75\x72\x65\115\145\164\150\157\x64\x20\x2f\x3e\15\12\40\x20\74\x2f\x53\x69\x67\156\145\x64\111\156\146\157\x3e\15\xa\x3c\57\x53\x69\x67\156\x61\164\165\162\x65\x3e";
    public $sigNode = null;
    public $idKeys = array();
    public $idNS = array();
    private $signedInfo = null;
    private $xPathCtx = null;
    private $canonicalMethod = null;
    private $prefix = '';
    private $searchpfx = "\x73\145\x63\x64\x73\x69\147";
    private $validatedNodes = null;
    public function __construct($id = "\x64\163")
    {
        $Pm = self::BASE_TEMPLATE;
        if (empty($id)) {
            goto N7;
        }
        $this->prefix = $id . "\72";
        $VJ = array("\x3c\x53", "\74\x2f\x53", "\170\155\154\156\x73\75");
        $KX = array("\74{$id}\72\123", "\x3c\x2f{$id}\72\123", "\170\x6d\154\156\x73\x3a{$id}\75");
        $Pm = str_replace($VJ, $KX, $Pm);
        N7:
        $DO = new DOMDocument();
        $DO->loadXML($Pm);
        $this->sigNode = $DO->documentElement;
    }
    private function resetXPathObj()
    {
        $this->xPathCtx = null;
    }
    private function getXPathObj()
    {
        if (!(empty($this->xPathCtx) && !empty($this->sigNode))) {
            goto XL;
        }
        $Lc = new DOMXPath($this->sigNode->ownerDocument);
        $Lc->registerNamespace("\163\145\x63\x64\x73\151\x67", self::XMLDSIGNS);
        $this->xPathCtx = $Lc;
        XL:
        return $this->xPathCtx;
    }
    public static function generateGUID($id = "\160\x66\x78")
    {
        $w7 = md5(uniqid(mt_rand(), true));
        $tK = $id . substr($w7, 0, 8) . "\55" . substr($w7, 8, 4) . "\55" . substr($w7, 12, 4) . "\x2d" . substr($w7, 16, 4) . "\55" . substr($w7, 20, 12);
        return $tK;
    }
    public static function generate_GUID($id = "\160\x66\x78")
    {
        return self::generateGUID($id);
    }
    public function locateSignature($JS, $KU = 0)
    {
        if ($JS instanceof DOMDocument) {
            goto oX;
        }
        $oi = $JS->ownerDocument;
        goto yS;
        oX:
        $oi = $JS;
        yS:
        if (!$oi) {
            goto xu;
        }
        $Lc = new DOMXPath($oi);
        $Lc->registerNamespace("\x73\x65\x63\144\163\151\147", self::XMLDSIGNS);
        $BJ = "\56\57\57\163\145\x63\144\x73\151\147\x3a\123\151\x67\156\x61\164\165\162\145";
        $tA = $Lc->query($BJ, $JS);
        $this->sigNode = $tA->item($KU);
        return $this->sigNode;
        xu:
        return null;
    }
    public function createNewSignNode($ci, $Or = null)
    {
        $oi = $this->sigNode->ownerDocument;
        if (!is_null($Or)) {
            goto TL;
        }
        $li = $oi->createElementNS(self::XMLDSIGNS, $this->prefix . $ci);
        goto O6;
        TL:
        $li = $oi->createElementNS(self::XMLDSIGNS, $this->prefix . $ci, $Or);
        O6:
        return $li;
    }
    public function setCanonicalMethod($kG)
    {
        switch ($kG) {
            case "\150\x74\x74\x70\72\57\x2f\167\x77\x77\56\x77\x33\56\x6f\162\x67\57\x54\122\57\x32\x30\x30\61\x2f\x52\x45\103\55\170\155\154\x2d\143\61\x34\x6e\55\x32\x30\x30\x31\x30\x33\61\x35":
            case "\x68\x74\x74\160\72\x2f\57\167\167\x77\56\x77\x33\x2e\157\x72\x67\x2f\x54\x52\x2f\x32\x30\60\x31\x2f\122\x45\103\x2d\x78\155\154\x2d\143\61\64\156\55\62\60\x30\x31\60\63\61\x35\x23\x57\151\x74\x68\103\157\x6d\155\x65\x6e\x74\x73":
            case "\150\164\x74\160\72\57\57\x77\x77\x77\x2e\167\63\56\157\x72\147\x2f\62\x30\x30\x31\x2f\x31\x30\x2f\x78\x6d\154\55\x65\170\143\55\143\x31\64\156\43":
            case "\x68\x74\x74\160\x3a\57\57\167\167\167\x2e\167\63\x2e\x6f\162\x67\x2f\62\60\60\61\x2f\61\60\x2f\170\x6d\154\55\x65\170\x63\55\143\61\64\156\43\127\x69\164\150\x43\157\155\x6d\x65\x6e\164\163":
                $this->canonicalMethod = $kG;
                goto Zy;
            default:
                throw new Exception("\x49\x6e\166\141\154\x69\144\x20\103\141\156\157\156\151\x63\x61\x6c\x20\115\145\x74\x68\157\x64");
        }
        it:
        Zy:
        if (!($Lc = $this->getXPathObj())) {
            goto oY;
        }
        $BJ = "\56\57" . $this->searchpfx . "\72\123\151\x67\156\145\144\x49\x6e\146\x6f";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($ji = $tA->item(0))) {
            goto IB;
        }
        $BJ = "\56\57" . $this->searchpfx . "\103\x61\x6e\x6f\x6e\151\143\141\x6c\151\172\141\x74\x69\157\x6e\115\145\164\x68\x6f\x64";
        $tA = $Lc->query($BJ, $ji);
        if ($Ch = $tA->item(0)) {
            goto Pc;
        }
        $Ch = $this->createNewSignNode("\x43\141\156\157\x6e\x69\143\141\154\151\x7a\141\x74\x69\157\156\115\145\164\150\x6f\144");
        $ji->insertBefore($Ch, $ji->firstChild);
        Pc:
        $Ch->setAttribute("\101\154\147\x6f\x72\151\x74\150\x6d", $this->canonicalMethod);
        IB:
        oY:
    }
    private function canonicalizeData($li, $qL, $zy = null, $MJ = null)
    {
        $me = false;
        $fR = false;
        switch ($qL) {
            case "\150\x74\164\x70\x3a\57\57\x77\x77\x77\x2e\x77\x33\x2e\x6f\162\x67\57\x54\122\57\62\60\60\61\x2f\x52\x45\103\55\x78\x6d\x6c\x2d\x63\x31\64\x6e\x2d\x32\x30\60\61\x30\x33\61\x35":
                $me = false;
                $fR = false;
                goto Bp;
            case "\x68\164\164\x70\x3a\57\57\167\x77\x77\x2e\167\x33\x2e\x6f\162\x67\57\x54\122\57\x32\x30\60\61\57\x52\x45\x43\55\170\155\154\55\143\x31\x34\156\55\x32\60\60\61\x30\x33\61\65\x23\x57\x69\x74\x68\103\157\x6d\x6d\145\156\x74\163":
                $fR = true;
                goto Bp;
            case "\150\164\x74\160\72\x2f\x2f\167\167\x77\56\167\63\x2e\x6f\x72\x67\57\62\x30\x30\61\x2f\61\x30\57\170\x6d\x6c\x2d\x65\170\143\x2d\x63\x31\64\156\43":
                $me = true;
                goto Bp;
            case "\150\164\x74\x70\72\57\x2f\167\167\x77\x2e\167\x33\56\157\x72\x67\x2f\62\60\x30\61\x2f\x31\x30\57\170\155\154\55\x65\170\143\x2d\x63\x31\x34\x6e\x23\127\151\x74\150\103\157\155\155\145\x6e\164\x73":
                $me = true;
                $fR = true;
                goto Bp;
        }
        Qr:
        Bp:
        if (!(is_null($zy) && $li instanceof DOMNode && $li->ownerDocument !== null && $li->isSameNode($li->ownerDocument->documentElement))) {
            goto kR;
        }
        $h0 = $li;
        qZ:
        if (!($Ml = $h0->previousSibling)) {
            goto oj;
        }
        if (!($Ml->nodeType == XML_PI_NODE || $Ml->nodeType == XML_COMMENT_NODE && $fR)) {
            goto rn;
        }
        goto oj;
        rn:
        $h0 = $Ml;
        goto qZ;
        oj:
        if (!($Ml == null)) {
            goto ll;
        }
        $li = $li->ownerDocument;
        ll:
        kR:
        return $li->C14N($me, $fR, $zy, $MJ);
    }
    public function canonicalizeSignedInfo()
    {
        $oi = $this->sigNode->ownerDocument;
        $qL = null;
        if (!$oi) {
            goto Sq;
        }
        $Lc = $this->getXPathObj();
        $BJ = "\x2e\57\x73\x65\143\144\163\151\147\72\123\151\147\x6e\145\x64\x49\x6e\146\157";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($yl = $tA->item(0))) {
            goto bE;
        }
        $BJ = "\56\57\163\x65\x63\x64\x73\151\x67\x3a\x43\141\156\157\156\151\143\x61\154\151\172\x61\x74\151\x6f\156\x4d\145\164\150\x6f\x64";
        $tA = $Lc->query($BJ, $yl);
        if (!($Ch = $tA->item(0))) {
            goto dG;
        }
        $qL = $Ch->getAttribute("\x41\154\147\157\x72\151\164\150\155");
        dG:
        $this->signedInfo = $this->canonicalizeData($yl, $qL);
        return $this->signedInfo;
        bE:
        Sq:
        return null;
    }
    public function calculateDigest($dk, $qB, $ny = true)
    {
        switch ($dk) {
            case self::SHA1:
                $WM = "\x73\150\141\x31";
                goto lo;
            case self::SHA256:
                $WM = "\163\x68\x61\x32\65\66";
                goto lo;
            case self::SHA384:
                $WM = "\x73\x68\x61\x33\x38\x34";
                goto lo;
            case self::SHA512:
                $WM = "\163\150\141\65\61\x32";
                goto lo;
            case self::RIPEMD160:
                $WM = "\x72\x69\x70\145\155\x64\x31\x36\x30";
                goto lo;
            default:
                throw new Exception("\103\141\x6e\156\x6f\x74\x20\166\x61\154\151\144\141\164\x65\x20\x64\x69\x67\145\x73\x74\72\x20\125\x6e\163\x75\x70\160\157\162\164\145\x64\x20\101\x6c\x67\157\x72\151\x74\x68\155\x20\x3c{$dk}\x3e");
        }
        Gh:
        lo:
        $h7 = hash($WM, $qB, true);
        if (!$ny) {
            goto LI;
        }
        $h7 = base64_encode($h7);
        LI:
        return $h7;
    }
    public function validateDigest($ej, $qB)
    {
        $Lc = new DOMXPath($ej->ownerDocument);
        $Lc->registerNamespace("\x73\145\x63\144\x73\x69\x67", self::XMLDSIGNS);
        $BJ = "\x73\164\x72\x69\x6e\x67\x28\56\57\163\145\143\144\163\x69\x67\72\104\x69\147\x65\163\x74\115\x65\x74\150\157\x64\x2f\x40\101\x6c\x67\x6f\x72\x69\x74\150\x6d\x29";
        $dk = $Lc->evaluate($BJ, $ej);
        $LX = $this->calculateDigest($dk, $qB, false);
        $BJ = "\x73\164\162\151\x6e\x67\50\x2e\x2f\x73\x65\143\144\x73\x69\147\72\104\151\147\x65\x73\164\x56\x61\154\x75\x65\x29";
        $dO = $Lc->evaluate($BJ, $ej);
        return $LX == base64_decode($dO);
    }
    public function processTransforms($ej, $bD, $mv = true)
    {
        $qB = $bD;
        $Lc = new DOMXPath($ej->ownerDocument);
        $Lc->registerNamespace("\163\x65\143\x64\x73\151\x67", self::XMLDSIGNS);
        $BJ = "\56\x2f\163\x65\x63\x64\163\x69\147\x3a\124\162\x61\156\x73\146\x6f\162\155\x73\57\x73\x65\143\x64\x73\x69\147\72\x54\162\141\156\x73\146\157\x72\155";
        $Xw = $Lc->query($BJ, $ej);
        $BY = "\x68\x74\164\x70\72\x2f\57\x77\x77\x77\56\167\63\x2e\x6f\x72\147\57\x54\x52\57\62\60\x30\61\57\x52\x45\x43\x2d\x78\x6d\154\x2d\x63\61\64\156\55\62\x30\x30\x31\60\x33\x31\65";
        $zy = null;
        $MJ = null;
        foreach ($Xw as $GA) {
            $o2 = $GA->getAttribute("\101\154\147\157\162\x69\164\x68\x6d");
            switch ($o2) {
                case "\150\164\164\160\72\x2f\x2f\167\x77\x77\56\167\63\56\x6f\x72\147\x2f\x32\x30\x30\61\x2f\x31\60\x2f\x78\x6d\154\x2d\145\170\143\x2d\x63\61\x34\x6e\43":
                case "\x68\x74\164\160\72\x2f\x2f\x77\167\167\56\x77\x33\56\157\162\x67\x2f\x32\60\60\x31\x2f\x31\60\57\170\x6d\154\x2d\145\x78\x63\x2d\x63\x31\64\x6e\x23\x57\151\x74\x68\x43\157\155\x6d\145\x6e\164\x73":
                    if (!$mv) {
                        goto RW;
                    }
                    $BY = $o2;
                    goto to;
                    RW:
                    $BY = "\150\164\x74\x70\x3a\x2f\x2f\167\167\x77\x2e\167\63\x2e\x6f\x72\x67\57\x32\x30\60\x31\57\x31\60\x2f\x78\x6d\154\55\x65\170\143\55\x63\61\64\x6e\x23";
                    to:
                    $li = $GA->firstChild;
                    c3:
                    if (!$li) {
                        goto Ge;
                    }
                    if (!($li->localName == "\111\156\143\154\165\163\x69\166\x65\x4e\x61\155\x65\163\160\x61\143\145\163")) {
                        goto Da;
                    }
                    if (!($h4 = $li->getAttribute("\x50\162\145\x66\x69\170\114\x69\x73\x74"))) {
                        goto TM;
                    }
                    $oh = array();
                    $dC = explode("\x20", $h4);
                    foreach ($dC as $h4) {
                        $xF = trim($h4);
                        if (empty($xF)) {
                            goto GL;
                        }
                        $oh[] = $xF;
                        GL:
                        n3:
                    }
                    sc:
                    if (!(count($oh) > 0)) {
                        goto hQ;
                    }
                    $MJ = $oh;
                    hQ:
                    TM:
                    goto Ge;
                    Da:
                    $li = $li->nextSibling;
                    goto c3;
                    Ge:
                    goto Uk;
                case "\150\x74\164\x70\x3a\x2f\x2f\167\167\x77\56\x77\x33\56\157\162\147\x2f\x54\x52\x2f\x32\x30\60\x31\57\122\x45\x43\55\170\x6d\x6c\55\x63\61\64\x6e\55\62\60\x30\x31\x30\x33\61\65":
                case "\150\164\164\160\x3a\57\57\x77\167\x77\x2e\x77\x33\56\x6f\x72\147\57\124\x52\x2f\x32\x30\x30\x31\57\x52\105\x43\x2d\x78\x6d\154\55\x63\61\64\156\x2d\62\60\60\x31\x30\63\x31\65\43\x57\151\x74\150\x43\x6f\155\x6d\x65\x6e\164\163":
                    if (!$mv) {
                        goto aj;
                    }
                    $BY = $o2;
                    goto Dt;
                    aj:
                    $BY = "\150\x74\x74\160\72\57\x2f\167\167\167\x2e\167\x33\x2e\157\162\x67\x2f\124\x52\x2f\62\60\x30\x31\57\122\x45\x43\x2d\x78\155\x6c\55\x63\x31\64\x6e\x2d\62\60\x30\x31\x30\63\x31\65";
                    Dt:
                    goto Uk;
                case "\x68\164\164\x70\x3a\x2f\x2f\x77\167\167\56\x77\63\56\157\x72\147\57\124\x52\57\61\x39\x39\71\x2f\x52\x45\103\55\170\x70\x61\164\x68\x2d\61\x39\x39\71\x31\61\x31\x36":
                    $li = $GA->firstChild;
                    Mi:
                    if (!$li) {
                        goto ya;
                    }
                    if (!($li->localName == "\x58\x50\141\164\150")) {
                        goto Nc;
                    }
                    $zy = array();
                    $zy["\x71\x75\x65\x72\171"] = "\x28\56\x2f\x2f\x2e\40\174\x20\56\x2f\57\x40\52\40\174\40\x2e\x2f\57\156\141\155\x65\163\x70\x61\143\145\x3a\72\52\x29\x5b" . $li->nodeValue . "\135";
                    $Dp["\156\x61\155\145\x73\x70\x61\143\x65\x73"] = array();
                    $D5 = $Lc->query("\56\57\156\x61\155\x65\163\160\x61\143\x65\72\x3a\x2a", $li);
                    foreach ($D5 as $jG) {
                        if (!($jG->localName != "\170\155\154")) {
                            goto DP;
                        }
                        $zy["\156\141\x6d\x65\x73\160\141\x63\x65\163"][$jG->localName] = $jG->nodeValue;
                        DP:
                        YQ:
                    }
                    hf:
                    goto ya;
                    Nc:
                    $li = $li->nextSibling;
                    goto Mi;
                    ya:
                    goto Uk;
            }
            xd:
            Uk:
            Av:
        }
        M0:
        if (!$qB instanceof DOMElement) {
            goto Fu;
        }
        $qB = $this->canonicalizeData($bD, $BY, $zy, $MJ);
        Fu:
        return $qB;
    }
    public function processRefNode($ej)
    {
        $FU = null;
        $mv = true;
        if ($Rs = $ej->getAttribute("\125\122\111")) {
            goto oH;
        }
        $mv = false;
        $FU = $ej->ownerDocument;
        goto FE;
        oH:
        $ed = parse_url($Rs);
        if (empty($ed["\160\x61\164\x68"])) {
            goto Z7;
        }
        $FU = file_get_contents($ed);
        goto T4;
        Z7:
        if ($vg = $ed["\146\x72\x61\147\155\x65\156\164"]) {
            goto L5;
        }
        $FU = $ej->ownerDocument;
        goto sL;
        L5:
        $mv = false;
        $D1 = new DOMXPath($ej->ownerDocument);
        if (!($this->idNS && is_array($this->idNS))) {
            goto aL;
        }
        foreach ($this->idNS as $q_ => $EN) {
            $D1->registerNamespace($q_, $EN);
            Qp:
        }
        wc:
        aL:
        $JC = "\100\x49\144\75\x22" . $vg . "\x22";
        if (!is_array($this->idKeys)) {
            goto U_;
        }
        foreach ($this->idKeys as $WI) {
            $JC .= "\40\x6f\162\40\100{$WI}\75\47{$vg}\x27";
            qE:
        }
        XZ:
        U_:
        $BJ = "\57\x2f\x2a\133" . $JC . "\135";
        $FU = $D1->query($BJ)->item(0);
        sL:
        T4:
        FE:
        $qB = $this->processTransforms($ej, $FU, $mv);
        if ($this->validateDigest($ej, $qB)) {
            goto ug;
        }
        return false;
        ug:
        if (!$FU instanceof DOMElement) {
            goto rT;
        }
        if (!empty($vg)) {
            goto B6;
        }
        $this->validatedNodes[] = $FU;
        goto SJ;
        B6:
        $this->validatedNodes[$vg] = $FU;
        SJ:
        rT:
        return true;
    }
    public function getRefNodeID($ej)
    {
        if (!($Rs = $ej->getAttribute("\125\122\111"))) {
            goto n2;
        }
        $ed = parse_url($Rs);
        if (!empty($ed["\160\141\164\x68"])) {
            goto uF;
        }
        if (!($vg = $ed["\146\162\141\x67\155\x65\156\x74"])) {
            goto y0;
        }
        return $vg;
        y0:
        uF:
        n2:
        return null;
    }
    public function getRefIDs()
    {
        $rm = array();
        $Lc = $this->getXPathObj();
        $BJ = "\x2e\57\x73\x65\143\144\x73\x69\x67\x3a\123\x69\x67\x6e\x65\144\x49\x6e\x66\157\x2f\x73\x65\x63\144\163\x69\x67\x3a\x52\x65\146\x65\x72\x65\x6e\143\x65";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($tA->length == 0)) {
            goto hK;
        }
        throw new Exception("\122\x65\x66\x65\162\x65\156\143\145\x20\x6e\x6f\x64\x65\x73\x20\156\157\x74\x20\x66\x6f\165\156\144");
        hK:
        foreach ($tA as $ej) {
            $rm[] = $this->getRefNodeID($ej);
            cp:
        }
        jV:
        return $rm;
    }
    public function validateReference()
    {
        $sU = $this->sigNode->ownerDocument->documentElement;
        if ($sU->isSameNode($this->sigNode)) {
            goto T9;
        }
        if (!($this->sigNode->parentNode != null)) {
            goto BW;
        }
        $this->sigNode->parentNode->removeChild($this->sigNode);
        BW:
        T9:
        $Lc = $this->getXPathObj();
        $BJ = "\x2e\x2f\x73\145\x63\144\x73\x69\147\72\x53\151\147\156\145\144\x49\x6e\x66\x6f\x2f\x73\145\143\x64\x73\x69\x67\x3a\122\145\146\x65\162\x65\x6e\143\x65";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($tA->length == 0)) {
            goto G3;
        }
        throw new Exception("\x52\x65\x66\145\x72\x65\x6e\143\145\40\156\157\x64\x65\163\40\156\x6f\x74\40\146\157\x75\156\144");
        G3:
        $this->validatedNodes = array();
        foreach ($tA as $ej) {
            if ($this->processRefNode($ej)) {
                goto V6;
            }
            $this->validatedNodes = null;
            throw new Exception("\x52\145\146\145\x72\x65\156\143\145\40\166\141\154\x69\144\x61\x74\x69\x6f\156\x20\146\x61\151\x6c\x65\144");
            V6:
            Dr:
        }
        th:
        return true;
    }
    private function addRefInternal($aF, $li, $o2, $eN = null, $a0 = null)
    {
        $id = null;
        $tn = null;
        $zA = "\x49\x64";
        $oW = true;
        $QP = false;
        if (!is_array($a0)) {
            goto oq;
        }
        $id = empty($a0["\x70\162\x65\146\151\x78"]) ? null : $a0["\160\x72\145\x66\x69\170"];
        $tn = empty($a0["\x70\162\x65\x66\151\x78\x5f\156\163"]) ? null : $a0["\160\x72\145\x66\x69\170\137\156\x73"];
        $zA = empty($a0["\151\x64\137\156\x61\x6d\x65"]) ? "\111\144" : $a0["\x69\144\137\x6e\x61\155\145"];
        $oW = !isset($a0["\x6f\166\145\162\167\162\x69\164\x65"]) ? true : (bool) $a0["\157\166\145\x72\167\x72\151\164\145"];
        $QP = !isset($a0["\x66\157\162\x63\x65\x5f\x75\x72\151"]) ? false : (bool) $a0["\146\157\x72\x63\145\137\x75\162\151"];
        oq:
        $Lg = $zA;
        if (empty($id)) {
            goto vX;
        }
        $Lg = $id . "\72" . $Lg;
        vX:
        $ej = $this->createNewSignNode("\122\145\x66\145\162\x65\156\x63\x65");
        $aF->appendChild($ej);
        if (!$li instanceof DOMDocument) {
            goto g5;
        }
        if ($QP) {
            goto rt;
        }
        goto LQ;
        g5:
        $Rs = null;
        if ($oW) {
            goto ws;
        }
        $Rs = $tn ? $li->getAttributeNS($tn, $zA) : $li->getAttribute($zA);
        ws:
        if (!empty($Rs)) {
            goto tn;
        }
        $Rs = self::generateGUID();
        $li->setAttributeNS($tn, $Lg, $Rs);
        tn:
        $ej->setAttribute("\125\122\x49", "\x23" . $Rs);
        goto LQ;
        rt:
        $ej->setAttribute("\x55\x52\111", '');
        LQ:
        $SW = $this->createNewSignNode("\124\x72\x61\x6e\x73\146\x6f\162\x6d\x73");
        $ej->appendChild($SW);
        if (is_array($eN)) {
            goto Kh;
        }
        if (!empty($this->canonicalMethod)) {
            goto Oq;
        }
        goto Lb;
        Kh:
        foreach ($eN as $GA) {
            $XG = $this->createNewSignNode("\124\162\141\156\x73\x66\157\162\155");
            $SW->appendChild($XG);
            if (is_array($GA) && !empty($GA["\x68\x74\x74\160\72\57\57\167\167\x77\56\167\x33\56\157\x72\147\x2f\x54\x52\57\61\71\x39\x39\57\122\x45\x43\x2d\x78\160\x61\164\x68\x2d\61\71\71\x39\61\61\61\66"]) && !empty($GA["\x68\x74\164\160\x3a\57\x2f\x77\167\x77\56\167\x33\56\157\x72\147\x2f\124\122\x2f\x31\71\x39\x39\x2f\122\105\103\x2d\x78\160\141\x74\150\x2d\61\x39\71\x39\x31\x31\x31\x36"]["\161\x75\145\x72\171"])) {
                goto x2;
            }
            $XG->setAttribute("\101\x6c\x67\x6f\x72\x69\x74\x68\x6d", $GA);
            goto dk;
            x2:
            $XG->setAttribute("\101\x6c\x67\157\162\x69\164\x68\155", "\150\164\164\160\x3a\x2f\x2f\167\x77\x77\56\167\63\56\157\162\x67\57\124\122\x2f\61\71\x39\x39\57\122\x45\x43\x2d\x78\160\141\x74\150\x2d\x31\71\71\x39\61\x31\x31\66");
            $wC = $this->createNewSignNode("\x58\120\x61\x74\x68", $GA["\150\x74\x74\x70\x3a\x2f\x2f\x77\167\x77\x2e\167\63\56\x6f\x72\x67\x2f\x54\122\57\x31\71\71\71\57\x52\105\103\55\x78\x70\141\x74\150\55\61\71\71\71\x31\x31\61\x36"]["\x71\x75\145\162\x79"]);
            $XG->appendChild($wC);
            if (empty($GA["\x68\x74\164\x70\x3a\57\x2f\167\167\167\56\167\63\x2e\157\x72\x67\57\124\122\57\x31\x39\x39\71\x2f\122\105\103\55\170\x70\x61\164\x68\55\x31\x39\71\71\61\61\61\66"]["\x6e\x61\x6d\x65\163\160\141\143\x65\163"])) {
                goto Co;
            }
            foreach ($GA["\x68\x74\164\x70\72\x2f\57\167\x77\x77\x2e\167\63\56\157\162\x67\57\124\x52\57\61\x39\x39\71\x2f\x52\105\103\x2d\170\x70\141\164\150\x2d\x31\71\71\71\x31\x31\61\66"]["\156\141\x6d\145\163\x70\141\143\x65\163"] as $id => $gI) {
                $wC->setAttributeNS("\x68\164\164\160\x3a\57\57\x77\167\167\56\167\x33\56\x6f\162\x67\x2f\x32\x30\x30\60\x2f\x78\155\154\x6e\x73\57", "\x78\155\x6c\x6e\163\x3a{$id}", $gI);
                pA:
            }
            ey:
            Co:
            dk:
            G8:
        }
        g6:
        goto Lb;
        Oq:
        $XG = $this->createNewSignNode("\124\162\141\156\x73\146\x6f\x72\155");
        $SW->appendChild($XG);
        $XG->setAttribute("\101\154\147\x6f\x72\151\x74\150\x6d", $this->canonicalMethod);
        Lb:
        $YY = $this->processTransforms($ej, $li);
        $LX = $this->calculateDigest($o2, $YY);
        $Fm = $this->createNewSignNode("\104\x69\147\145\163\x74\115\x65\x74\150\157\144");
        $ej->appendChild($Fm);
        $Fm->setAttribute("\101\154\x67\x6f\162\x69\164\150\155", $o2);
        $dO = $this->createNewSignNode("\104\x69\x67\145\x73\164\126\141\154\x75\x65", $LX);
        $ej->appendChild($dO);
    }
    public function addReference($li, $o2, $eN = null, $a0 = null)
    {
        if (!($Lc = $this->getXPathObj())) {
            goto Ln;
        }
        $BJ = "\56\x2f\x73\x65\143\144\163\151\147\72\x53\151\x67\x6e\x65\x64\x49\156\146\x6f";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($x4 = $tA->item(0))) {
            goto lm;
        }
        $this->addRefInternal($x4, $li, $o2, $eN, $a0);
        lm:
        Ln:
    }
    public function addReferenceList($EI, $o2, $eN = null, $a0 = null)
    {
        if (!($Lc = $this->getXPathObj())) {
            goto bG;
        }
        $BJ = "\x2e\x2f\x73\x65\143\144\x73\x69\147\x3a\x53\151\x67\x6e\145\144\x49\156\x66\157";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($x4 = $tA->item(0))) {
            goto ER;
        }
        foreach ($EI as $li) {
            $this->addRefInternal($x4, $li, $o2, $eN, $a0);
            kq:
        }
        H_:
        ER:
        bG:
    }
    public function addObject($qB, $rn = null, $kC = null)
    {
        $uE = $this->createNewSignNode("\117\142\152\x65\143\164");
        $this->sigNode->appendChild($uE);
        if (empty($rn)) {
            goto tm;
        }
        $uE->setAttribute("\115\x69\x6d\x65\124\x79\x70\x65", $rn);
        tm:
        if (empty($kC)) {
            goto EA;
        }
        $uE->setAttribute("\105\156\x63\x6f\x64\x69\156\147", $kC);
        EA:
        if ($qB instanceof DOMElement) {
            goto L9;
        }
        $H3 = $this->sigNode->ownerDocument->createTextNode($qB);
        goto NX;
        L9:
        $H3 = $this->sigNode->ownerDocument->importNode($qB, true);
        NX:
        $uE->appendChild($H3);
        return $uE;
    }
    public function locateKey($li = null)
    {
        if (!empty($li)) {
            goto Id;
        }
        $li = $this->sigNode;
        Id:
        if ($li instanceof DOMNode) {
            goto m2;
        }
        return null;
        m2:
        if (!($oi = $li->ownerDocument)) {
            goto Ki;
        }
        $Lc = new DOMXPath($oi);
        $Lc->registerNamespace("\163\145\x63\144\x73\151\x67", self::XMLDSIGNS);
        $BJ = "\163\x74\x72\x69\156\x67\50\x2e\57\163\145\143\144\163\151\x67\72\123\x69\147\x6e\x65\x64\x49\156\146\157\x2f\163\145\x63\x64\x73\151\x67\x3a\x53\x69\147\156\x61\x74\x75\x72\145\x4d\145\x74\150\x6f\144\57\x40\x41\154\147\157\x72\151\164\x68\155\x29";
        $o2 = $Lc->evaluate($BJ, $li);
        if (!$o2) {
            goto rJ;
        }
        try {
            $qX = new XMLSecurityKey($o2, array("\164\x79\x70\145" => "\160\165\x62\x6c\151\143"));
        } catch (Exception $w4) {
            return null;
        }
        return $qX;
        rJ:
        Ki:
        return null;
    }
    public function verify($qX)
    {
        $oi = $this->sigNode->ownerDocument;
        $Lc = new DOMXPath($oi);
        $Lc->registerNamespace("\x73\x65\143\x64\x73\x69\x67", self::XMLDSIGNS);
        $BJ = "\163\164\162\151\156\147\x28\x2e\x2f\x73\x65\x63\144\163\151\147\x3a\123\151\147\156\x61\164\165\162\x65\x56\141\x6c\165\x65\x29";
        $eD = $Lc->evaluate($BJ, $this->sigNode);
        if (!empty($eD)) {
            goto bw;
        }
        throw new Exception("\125\x6e\x61\x62\154\x65\40\164\157\x20\154\157\143\141\164\145\40\123\151\147\156\141\164\x75\162\145\x56\141\x6c\x75\145");
        bw:
        return $qX->verifySignature($this->signedInfo, base64_decode($eD));
    }
    public function signData($qX, $qB)
    {
        return $qX->signData($qB);
    }
    public function sign($qX, $cw = null)
    {
        if (!($cw != null)) {
            goto VT;
        }
        $this->resetXPathObj();
        $this->appendSignature($cw);
        $this->sigNode = $cw->lastChild;
        VT:
        if (!($Lc = $this->getXPathObj())) {
            goto C8;
        }
        $BJ = "\x2e\x2f\x73\x65\143\144\163\x69\147\72\123\151\x67\156\x65\x64\x49\x6e\x66\157";
        $tA = $Lc->query($BJ, $this->sigNode);
        if (!($x4 = $tA->item(0))) {
            goto k8;
        }
        $BJ = "\x2e\x2f\x73\x65\x63\x64\x73\x69\147\72\x53\151\x67\156\x61\x74\165\162\x65\x4d\x65\x74\150\x6f\x64";
        $tA = $Lc->query($BJ, $x4);
        $u2 = $tA->item(0);
        $u2->setAttribute("\x41\154\147\157\162\x69\164\x68\155", $qX->type);
        $qB = $this->canonicalizeData($x4, $this->canonicalMethod);
        $eD = base64_encode($this->signData($qX, $qB));
        $b1 = $this->createNewSignNode("\123\151\147\x6e\x61\164\x75\162\145\x56\x61\154\x75\145", $eD);
        if ($NA = $x4->nextSibling) {
            goto yV;
        }
        $this->sigNode->appendChild($b1);
        goto EH;
        yV:
        $NA->parentNode->insertBefore($b1, $NA);
        EH:
        k8:
        C8:
    }
    public function appendCert()
    {
    }
    public function appendKey($qX, $Lj = null)
    {
        $qX->serializeKey($Lj);
    }
    public function insertSignature($li, $WH = null)
    {
        $s6 = $li->ownerDocument;
        $KM = $s6->importNode($this->sigNode, true);
        if ($WH == null) {
            goto qx;
        }
        return $li->insertBefore($KM, $WH);
        goto zp;
        qx:
        return $li->insertBefore($KM);
        zp:
    }
    public function appendSignature($Ux, $i0 = false)
    {
        $WH = $i0 ? $Ux->firstChild : null;
        return $this->insertSignature($Ux, $WH);
    }
    public static function get509XCert($U2, $ha = true)
    {
        $eW = self::staticGet509XCerts($U2, $ha);
        if (empty($eW)) {
            goto nx;
        }
        return $eW[0];
        nx:
        return '';
    }
    public static function staticGet509XCerts($eW, $ha = true)
    {
        if ($ha) {
            goto y2;
        }
        return array($eW);
        goto jR;
        y2:
        $qB = '';
        $JM = array();
        $EH = explode("\12", $eW);
        $Bu = false;
        foreach ($EH as $qU) {
            if (!$Bu) {
                goto Rz;
            }
            if (!(strncmp($qU, "\x2d\x2d\x2d\x2d\55\105\x4e\104\x20\103\x45\122\x54\111\x46\111\x43\101\x54\x45", 20) == 0)) {
                goto iH;
            }
            $Bu = false;
            $JM[] = $qB;
            $qB = '';
            goto Ck;
            iH:
            $qB .= trim($qU);
            goto h_;
            Rz:
            if (!(strncmp($qU, "\55\x2d\55\x2d\x2d\x42\x45\x47\111\116\40\103\105\122\x54\111\106\x49\x43\101\124\x45", 22) == 0)) {
                goto LV;
            }
            $Bu = true;
            LV:
            h_:
            Ck:
        }
        Si:
        return $JM;
        jR:
    }
    public static function staticAdd509Cert($S_, $U2, $ha = true, $b7 = false, $Lc = null, $a0 = null)
    {
        if (!$b7) {
            goto gy;
        }
        $U2 = file_get_contents($U2);
        gy:
        if ($S_ instanceof DOMElement) {
            goto nD;
        }
        throw new Exception("\111\156\x76\141\x6c\151\144\40\x70\141\x72\x65\156\164\x20\116\x6f\144\x65\40\x70\141\162\x61\155\145\x74\145\162");
        nD:
        $xt = $S_->ownerDocument;
        if (!empty($Lc)) {
            goto qh;
        }
        $Lc = new DOMXPath($S_->ownerDocument);
        $Lc->registerNamespace("\163\x65\143\x64\163\151\147", self::XMLDSIGNS);
        qh:
        $BJ = "\56\57\x73\x65\143\x64\x73\151\x67\x3a\113\145\x79\x49\x6e\146\157";
        $tA = $Lc->query($BJ, $S_);
        $TL = $tA->item(0);
        $eb = '';
        if (!$TL) {
            goto WT;
        }
        $h4 = $TL->lookupPrefix(self::XMLDSIGNS);
        if (empty($h4)) {
            goto cH;
        }
        $eb = $h4 . "\72";
        cH:
        goto Vu;
        WT:
        $h4 = $S_->lookupPrefix(self::XMLDSIGNS);
        if (empty($h4)) {
            goto y6;
        }
        $eb = $h4 . "\72";
        y6:
        $Zt = false;
        $TL = $xt->createElementNS(self::XMLDSIGNS, $eb . "\x4b\145\x79\x49\156\146\157");
        $BJ = "\56\57\x73\x65\x63\144\163\151\x67\x3a\117\142\x6a\x65\143\x74";
        $tA = $Lc->query($BJ, $S_);
        if (!($bu = $tA->item(0))) {
            goto NA;
        }
        $bu->parentNode->insertBefore($TL, $bu);
        $Zt = true;
        NA:
        if ($Zt) {
            goto BZ;
        }
        $S_->appendChild($TL);
        BZ:
        Vu:
        $eW = self::staticGet509XCerts($U2, $ha);
        $f_ = $xt->createElementNS(self::XMLDSIGNS, $eb . "\130\65\x30\x39\x44\141\164\x61");
        $TL->appendChild($f_);
        $qQ = false;
        $wI = false;
        if (!is_array($a0)) {
            goto sz;
        }
        if (empty($a0["\x69\163\x73\165\145\x72\123\x65\162\151\x61\154"])) {
            goto U1;
        }
        $qQ = true;
        U1:
        if (empty($a0["\163\x75\142\152\x65\x63\164\116\x61\155\x65"])) {
            goto Hr;
        }
        $wI = true;
        Hr:
        sz:
        foreach ($eW as $VM) {
            if (!($qQ || $wI)) {
                goto Bh;
            }
            if (!($R1 = openssl_x509_parse("\x2d\x2d\55\55\55\x42\105\x47\111\x4e\40\x43\105\x52\124\x49\x46\111\103\101\x54\x45\x2d\x2d\55\x2d\x2d\xa" . chunk_split($VM, 64, "\12") . "\55\x2d\x2d\55\x2d\105\x4e\104\x20\x43\105\122\124\x49\x46\x49\103\x41\x54\105\55\x2d\55\55\55\xa"))) {
                goto w5;
            }
            if (!($wI && !empty($R1["\163\x75\x62\152\x65\x63\x74"]))) {
                goto hP;
            }
            if (is_array($R1["\163\x75\x62\152\145\x63\164"])) {
                goto G1;
            }
            $ta = $R1["\x69\x73\x73\165\x65\x72"];
            goto JW;
            G1:
            $wv = array();
            foreach ($R1["\x73\165\142\152\x65\x63\x74"] as $gH => $Or) {
                if (is_array($Or)) {
                    goto Lq;
                }
                array_unshift($wv, "{$gH}\75{$Or}");
                goto G2;
                Lq:
                foreach ($Or as $G6) {
                    array_unshift($wv, "{$gH}\75{$G6}");
                    eY:
                }
                mS:
                G2:
                lG:
            }
            ik:
            $ta = implode("\54", $wv);
            JW:
            $oM = $xt->createElementNS(self::XMLDSIGNS, $eb . "\x58\x35\x30\71\x53\x75\x62\x6a\145\x63\164\116\x61\x6d\x65", $ta);
            $f_->appendChild($oM);
            hP:
            if (!($qQ && !empty($R1["\151\x73\x73\x75\145\x72"]) && !empty($R1["\163\145\162\151\141\154\x4e\165\155\x62\x65\x72"]))) {
                goto lS;
            }
            if (is_array($R1["\151\x73\x73\165\145\x72"])) {
                goto cc;
            }
            $df = $R1["\x69\x73\163\165\x65\x72"];
            goto CG;
            cc:
            $wv = array();
            foreach ($R1["\151\x73\x73\165\145\162"] as $gH => $Or) {
                array_unshift($wv, "{$gH}\75{$Or}");
                Fo:
            }
            mx:
            $df = implode("\x2c", $wv);
            CG:
            $D3 = $xt->createElementNS(self::XMLDSIGNS, $eb . "\130\65\60\x39\111\163\x73\165\145\162\123\145\x72\x69\x61\x6c");
            $f_->appendChild($D3);
            $gO = $xt->createElementNS(self::XMLDSIGNS, $eb . "\x58\65\x30\71\x49\163\163\x75\145\x72\x4e\x61\x6d\x65", $df);
            $D3->appendChild($gO);
            $gO = $xt->createElementNS(self::XMLDSIGNS, $eb . "\x58\x35\x30\71\x53\145\162\151\x61\x6c\116\165\x6d\x62\x65\162", $R1["\x73\145\x72\151\x61\x6c\116\x75\155\x62\145\162"]);
            $D3->appendChild($gO);
            lS:
            w5:
            Bh:
            $SJ = $xt->createElementNS(self::XMLDSIGNS, $eb . "\130\x35\60\x39\103\x65\x72\164\x69\x66\x69\x63\141\x74\x65", $VM);
            $f_->appendChild($SJ);
            Gu:
        }
        pQ:
    }
    public function add509Cert($U2, $ha = true, $b7 = false, $a0 = null)
    {
        if (!($Lc = $this->getXPathObj())) {
            goto VW;
        }
        self::staticAdd509Cert($this->sigNode, $U2, $ha, $b7, $Lc, $a0);
        VW:
    }
    public function appendToKeyInfo($li)
    {
        $S_ = $this->sigNode;
        $xt = $S_->ownerDocument;
        $Lc = $this->getXPathObj();
        if (!empty($Lc)) {
            goto RU;
        }
        $Lc = new DOMXPath($S_->ownerDocument);
        $Lc->registerNamespace("\x73\145\143\x64\163\x69\x67", self::XMLDSIGNS);
        RU:
        $BJ = "\x2e\x2f\163\x65\x63\144\163\151\x67\x3a\x4b\145\x79\x49\156\x66\x6f";
        $tA = $Lc->query($BJ, $S_);
        $TL = $tA->item(0);
        if ($TL) {
            goto O8;
        }
        $eb = '';
        $h4 = $S_->lookupPrefix(self::XMLDSIGNS);
        if (empty($h4)) {
            goto ah;
        }
        $eb = $h4 . "\x3a";
        ah:
        $Zt = false;
        $TL = $xt->createElementNS(self::XMLDSIGNS, $eb . "\x4b\x65\171\x49\156\x66\157");
        $BJ = "\56\57\x73\145\143\144\163\151\147\72\117\142\x6a\x65\143\164";
        $tA = $Lc->query($BJ, $S_);
        if (!($bu = $tA->item(0))) {
            goto mo;
        }
        $bu->parentNode->insertBefore($TL, $bu);
        $Zt = true;
        mo:
        if ($Zt) {
            goto y8;
        }
        $S_->appendChild($TL);
        y8:
        O8:
        $TL->appendChild($li);
        return $TL;
    }
    public function getValidatedNodes()
    {
        return $this->validatedNodes;
    }
}
class XMLSecEnc
{
    const template = "\x3c\x78\x65\156\x63\x3a\x45\156\x63\x72\171\x70\164\x65\x64\x44\141\x74\141\x20\x78\155\154\x6e\x73\72\170\x65\156\143\75\47\150\164\164\160\x3a\x2f\57\x77\167\x77\56\x77\63\56\157\162\x67\x2f\x32\60\60\x31\x2f\60\64\x2f\170\155\154\x65\156\x63\43\x27\76\xd\12\x20\x20\x20\x3c\x78\145\156\143\x3a\103\151\160\150\145\x72\104\141\164\141\76\15\xa\x20\x20\40\x20\x20\40\74\x78\145\156\143\x3a\103\x69\x70\x68\x65\162\126\x61\154\x75\145\x3e\x3c\x2f\x78\145\156\x63\72\x43\x69\160\150\x65\162\x56\141\154\x75\145\x3e\15\xa\40\x20\x20\x3c\x2f\170\x65\156\143\72\x43\151\x70\150\x65\x72\x44\141\x74\141\x3e\xd\12\74\57\170\x65\x6e\x63\72\x45\156\x63\162\x79\x70\164\x65\x64\104\x61\x74\x61\x3e";
    const Element = "\150\x74\x74\160\72\x2f\x2f\167\x77\x77\x2e\x77\x33\56\157\162\147\57\x32\60\x30\61\57\60\64\x2f\x78\155\x6c\x65\156\143\43\105\x6c\x65\155\x65\x6e\x74";
    const Content = "\150\164\164\160\72\57\x2f\x77\x77\x77\x2e\x77\63\x2e\157\162\x67\x2f\x32\60\60\61\x2f\x30\64\x2f\x78\155\154\x65\x6e\x63\x23\103\x6f\x6e\x74\x65\156\x74";
    const URI = 3;
    const XMLENCNS = "\150\164\164\160\x3a\57\57\167\167\x77\x2e\x77\63\56\157\162\x67\57\62\x30\60\x31\x2f\60\64\57\x78\x6d\x6c\145\156\143\43";
    private $encdoc = null;
    private $rawNode = null;
    public $type = null;
    public $encKey = null;
    private $references = array();
    public function __construct()
    {
        $this->_resetTemplate();
    }
    private function _resetTemplate()
    {
        $this->encdoc = new DOMDocument();
        $this->encdoc->loadXML(self::template);
    }
    public function addReference($ci, $li, $i9)
    {
        if ($li instanceof DOMNode) {
            goto B4;
        }
        throw new Exception("\44\156\x6f\144\145\40\151\x73\40\x6e\157\164\x20\x6f\146\x20\164\x79\x70\x65\x20\x44\117\115\116\157\144\145");
        B4:
        $Wh = $this->encdoc;
        $this->_resetTemplate();
        $k4 = $this->encdoc;
        $this->encdoc = $Wh;
        $K_ = XMLSecurityDSig::generateGUID();
        $h0 = $k4->documentElement;
        $h0->setAttribute("\x49\144", $K_);
        $this->references[$ci] = array("\156\x6f\x64\x65" => $li, "\164\171\160\145" => $i9, "\x65\x6e\x63\x6e\x6f\x64\145" => $k4, "\162\x65\x66\x75\x72\x69" => $K_);
    }
    public function setNode($li)
    {
        $this->rawNode = $li;
    }
    public function encryptNode($qX, $KX = true)
    {
        $qB = '';
        if (!empty($this->rawNode)) {
            goto Zv;
        }
        throw new Exception("\116\x6f\144\145\x20\164\157\40\145\x6e\143\x72\x79\x70\164\x20\150\x61\163\40\x6e\157\164\x20\142\x65\145\156\40\x73\145\164");
        Zv:
        if ($qX instanceof XMLSecurityKey) {
            goto AW;
        }
        throw new Exception("\x49\x6e\166\141\x6c\151\144\x20\113\145\171");
        AW:
        $oi = $this->rawNode->ownerDocument;
        $D1 = new DOMXPath($this->encdoc);
        $U9 = $D1->query("\x2f\x78\145\x6e\x63\x3a\x45\x6e\x63\162\171\160\164\145\144\104\141\x74\141\57\170\145\156\143\72\x43\x69\160\x68\145\162\104\x61\164\x61\x2f\170\145\156\x63\x3a\x43\151\160\x68\145\162\126\141\154\165\x65");
        $IA = $U9->item(0);
        if (!($IA == null)) {
            goto Yj;
        }
        throw new Exception("\105\162\x72\157\162\x20\x6c\x6f\x63\141\164\151\x6e\x67\40\103\151\x70\150\x65\x72\126\141\154\x75\x65\40\x65\x6c\x65\155\145\156\164\x20\x77\151\164\x68\x69\156\40\x74\145\x6d\x70\154\x61\164\145");
        Yj:
        switch ($this->type) {
            case self::Element:
                $qB = $oi->saveXML($this->rawNode);
                $this->encdoc->documentElement->setAttribute("\x54\171\160\x65", self::Element);
                goto k3;
            case self::Content:
                $W5 = $this->rawNode->childNodes;
                foreach ($W5 as $NW) {
                    $qB .= $oi->saveXML($NW);
                    nT:
                }
                wE:
                $this->encdoc->documentElement->setAttribute("\x54\x79\160\145", self::Content);
                goto k3;
            default:
                throw new Exception("\x54\171\x70\145\x20\151\163\x20\143\x75\x72\x72\145\x6e\x74\x6c\171\40\156\157\x74\x20\x73\x75\160\x70\x6f\162\164\145\x64");
        }
        yN:
        k3:
        $Bt = $this->encdoc->documentElement->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\156\143\x3a\x45\x6e\x63\x72\171\x70\164\151\x6f\156\115\x65\x74\x68\157\144"));
        $Bt->setAttribute("\101\154\147\x6f\162\151\x74\150\155", $qX->getAlgorithm());
        $IA->parentNode->parentNode->insertBefore($Bt, $IA->parentNode->parentNode->firstChild);
        $AH = base64_encode($qX->encryptData($qB));
        $Or = $this->encdoc->createTextNode($AH);
        $IA->appendChild($Or);
        if ($KX) {
            goto oW;
        }
        return $this->encdoc->documentElement;
        goto g1;
        oW:
        switch ($this->type) {
            case self::Element:
                if (!($this->rawNode->nodeType == XML_DOCUMENT_NODE)) {
                    goto KP;
                }
                return $this->encdoc;
                KP:
                $ma = $this->rawNode->ownerDocument->importNode($this->encdoc->documentElement, true);
                $this->rawNode->parentNode->replaceChild($ma, $this->rawNode);
                return $ma;
            case self::Content:
                $ma = $this->rawNode->ownerDocument->importNode($this->encdoc->documentElement, true);
                Kz:
                if (!$this->rawNode->firstChild) {
                    goto Lx;
                }
                $this->rawNode->removeChild($this->rawNode->firstChild);
                goto Kz;
                Lx:
                $this->rawNode->appendChild($ma);
                return $ma;
        }
        MJ:
        bn:
        g1:
    }
    public function encryptReferences($qX)
    {
        $wB = $this->rawNode;
        $Ce = $this->type;
        foreach ($this->references as $ci => $Du) {
            $this->encdoc = $Du["\145\156\x63\x6e\x6f\x64\145"];
            $this->rawNode = $Du["\x6e\x6f\144\x65"];
            $this->type = $Du["\x74\171\160\145"];
            try {
                $Fe = $this->encryptNode($qX);
                $this->references[$ci]["\145\156\x63\x6e\x6f\x64\145"] = $Fe;
            } catch (Exception $w4) {
                $this->rawNode = $wB;
                $this->type = $Ce;
                throw $w4;
            }
            Kq:
        }
        Dg:
        $this->rawNode = $wB;
        $this->type = $Ce;
    }
    public function getCipherValue()
    {
        if (!empty($this->rawNode)) {
            goto VC;
        }
        throw new Exception("\116\157\x64\145\40\164\x6f\x20\144\x65\143\162\171\x70\164\x20\150\141\x73\x20\x6e\157\164\x20\142\145\145\x6e\x20\x73\x65\x74");
        VC:
        $oi = $this->rawNode->ownerDocument;
        $D1 = new DOMXPath($oi);
        $D1->registerNamespace("\x78\x6d\x6c\x65\x6e\143\x72", self::XMLENCNS);
        $BJ = "\x2e\x2f\170\x6d\154\x65\156\143\x72\72\x43\x69\160\x68\145\162\x44\x61\164\141\x2f\170\155\x6c\x65\x6e\x63\162\72\103\x69\160\150\x65\162\126\x61\x6c\x75\x65";
        $tA = $D1->query($BJ, $this->rawNode);
        $li = $tA->item(0);
        if ($li) {
            goto vz;
        }
        return null;
        vz:
        return base64_decode($li->nodeValue);
    }
    public function decryptNode($qX, $KX = true)
    {
        if ($qX instanceof XMLSecurityKey) {
            goto xi;
        }
        throw new Exception("\111\156\166\141\154\151\144\40\x4b\145\x79");
        xi:
        $WX = $this->getCipherValue();
        if ($WX) {
            goto Ti;
        }
        throw new Exception("\x43\x61\x6e\156\157\164\x20\x6c\x6f\143\141\164\145\x20\x65\x6e\x63\162\x79\x70\164\x65\x64\40\x64\141\x74\x61");
        goto LE;
        Ti:
        $xJ = $qX->decryptData($WX);
        if ($KX) {
            goto jt;
        }
        return $xJ;
        goto MI;
        jt:
        switch ($this->type) {
            case self::Element:
                $Gh = new DOMDocument();
                $Gh->loadXML($xJ);
                if (!($this->rawNode->nodeType == XML_DOCUMENT_NODE)) {
                    goto f5;
                }
                return $Gh;
                f5:
                $ma = $this->rawNode->ownerDocument->importNode($Gh->documentElement, true);
                $this->rawNode->parentNode->replaceChild($ma, $this->rawNode);
                return $ma;
            case self::Content:
                if ($this->rawNode->nodeType == XML_DOCUMENT_NODE) {
                    goto ve;
                }
                $oi = $this->rawNode->ownerDocument;
                goto dI;
                ve:
                $oi = $this->rawNode;
                dI:
                $qT = $oi->createDocumentFragment();
                $qT->appendXML($xJ);
                $Lj = $this->rawNode->parentNode;
                $Lj->replaceChild($qT, $this->rawNode);
                return $Lj;
            default:
                return $xJ;
        }
        kC:
        FM:
        MI:
        LE:
    }
    public function encryptKey($lv, $pW, $HD = true)
    {
        if (!(!$lv instanceof XMLSecurityKey || !$pW instanceof XMLSecurityKey)) {
            goto oe;
        }
        throw new Exception("\111\156\166\x61\154\151\x64\x20\x4b\145\x79");
        oe:
        $hZ = base64_encode($lv->encryptData($pW->key));
        $L0 = $this->encdoc->documentElement;
        $ZS = $this->encdoc->createElementNS(self::XMLENCNS, "\x78\x65\156\x63\72\x45\x6e\x63\x72\171\160\164\x65\x64\x4b\145\171");
        if ($HD) {
            goto d5;
        }
        $this->encKey = $ZS;
        goto p4;
        d5:
        $TL = $L0->insertBefore($this->encdoc->createElementNS("\x68\164\x74\x70\x3a\x2f\57\x77\167\167\56\167\x33\56\157\162\147\x2f\x32\60\60\x30\x2f\x30\x39\x2f\x78\x6d\x6c\x64\x73\x69\147\x23", "\x64\x73\x69\147\72\113\145\171\x49\156\x66\x6f"), $L0->firstChild);
        $TL->appendChild($ZS);
        p4:
        $Bt = $ZS->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\x65\156\143\x3a\105\x6e\x63\162\171\x70\164\151\x6f\156\x4d\145\164\x68\157\144"));
        $Bt->setAttribute("\x41\154\147\157\162\x69\x74\150\x6d", $lv->getAlgorithm());
        if (empty($lv->name)) {
            goto gR;
        }
        $TL = $ZS->appendChild($this->encdoc->createElementNS("\x68\x74\x74\x70\x3a\57\x2f\167\167\167\56\x77\x33\56\157\x72\x67\x2f\62\x30\60\60\57\x30\71\57\x78\155\154\144\x73\151\147\x23", "\144\x73\151\147\72\x4b\145\x79\111\156\146\157"));
        $TL->appendChild($this->encdoc->createElementNS("\150\x74\x74\x70\x3a\57\57\167\x77\167\56\167\63\56\157\162\x67\57\62\x30\60\60\x2f\60\71\x2f\170\155\x6c\144\163\x69\x67\43", "\x64\163\x69\x67\72\x4b\x65\x79\116\141\x6d\x65", $lv->name));
        gR:
        $tY = $ZS->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\x78\x65\x6e\143\72\103\151\x70\x68\145\162\x44\141\x74\141"));
        $tY->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\x65\156\143\72\x43\151\160\150\x65\x72\x56\x61\154\x75\x65", $hZ));
        if (!(is_array($this->references) && count($this->references) > 0)) {
            goto ea;
        }
        $OB = $ZS->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\x65\x6e\143\x3a\x52\x65\x66\x65\162\145\x6e\143\x65\x4c\x69\163\x74"));
        foreach ($this->references as $ci => $Du) {
            $K_ = $Du["\x72\145\x66\x75\x72\151"];
            $Z8 = $OB->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\x65\x6e\143\72\x44\x61\x74\141\x52\x65\x66\145\x72\145\x6e\x63\145"));
            $Z8->setAttribute("\x55\122\111", "\x23" . $K_);
            IU:
        }
        s4:
        ea:
        return;
    }
    public function decryptKey($ZS)
    {
        if ($ZS->isEncrypted) {
            goto mL;
        }
        throw new Exception("\113\x65\x79\x20\x69\163\40\156\157\164\x20\x45\x6e\143\x72\x79\160\x74\145\x64");
        mL:
        if (!empty($ZS->key)) {
            goto lT;
        }
        throw new Exception("\x4b\145\x79\x20\x69\163\x20\x6d\151\x73\163\x69\x6e\x67\40\144\141\164\141\40\x74\x6f\40\x70\145\x72\146\x6f\162\155\x20\x74\150\x65\40\144\x65\x63\162\x79\x70\164\x69\x6f\x6e");
        lT:
        return $this->decryptNode($ZS, false);
    }
    public function locateEncryptedData($h0)
    {
        if ($h0 instanceof DOMDocument) {
            goto g_;
        }
        $oi = $h0->ownerDocument;
        goto Xb;
        g_:
        $oi = $h0;
        Xb:
        if (!$oi) {
            goto cq;
        }
        $Lc = new DOMXPath($oi);
        $BJ = "\x2f\x2f\52\x5b\154\x6f\143\x61\154\55\x6e\141\x6d\145\50\x29\x3d\x27\x45\156\x63\x72\x79\160\164\x65\144\104\141\164\141\x27\40\x61\156\x64\x20\156\x61\x6d\145\x73\x70\x61\143\x65\x2d\x75\x72\x69\x28\51\x3d\47" . self::XMLENCNS . "\47\135";
        $tA = $Lc->query($BJ);
        return $tA->item(0);
        cq:
        return null;
    }
    public function locateKey($li = null)
    {
        if (!empty($li)) {
            goto rr;
        }
        $li = $this->rawNode;
        rr:
        if ($li instanceof DOMNode) {
            goto o_;
        }
        return null;
        o_:
        if (!($oi = $li->ownerDocument)) {
            goto St;
        }
        $Lc = new DOMXPath($oi);
        $Lc->registerNamespace("\x78\155\154\163\145\x63\x65\156\143", self::XMLENCNS);
        $BJ = "\56\x2f\57\x78\155\x6c\163\x65\x63\x65\x6e\143\x3a\x45\156\143\x72\x79\x70\164\151\x6f\x6e\x4d\145\x74\150\157\144";
        $tA = $Lc->query($BJ, $li);
        if (!($TG = $tA->item(0))) {
            goto ss;
        }
        $tI = $TG->getAttribute("\101\x6c\x67\x6f\x72\x69\x74\150\155");
        try {
            $qX = new XMLSecurityKey($tI, array("\164\171\160\x65" => "\160\x72\151\x76\141\x74\145"));
        } catch (Exception $w4) {
            return null;
        }
        return $qX;
        ss:
        St:
        return null;
    }
    public static function staticLocateKeyInfo($kb = null, $li = null)
    {
        if (!(empty($li) || !$li instanceof DOMNode)) {
            goto tO;
        }
        return null;
        tO:
        $oi = $li->ownerDocument;
        if ($oi) {
            goto Tm;
        }
        return null;
        Tm:
        $Lc = new DOMXPath($oi);
        $Lc->registerNamespace("\x78\155\x6c\x73\145\x63\x65\156\x63", self::XMLENCNS);
        $Lc->registerNamespace("\170\155\x6c\163\145\143\x64\x73\151\x67", XMLSecurityDSig::XMLDSIGNS);
        $BJ = "\56\x2f\x78\155\x6c\x73\x65\143\x64\163\x69\147\72\x4b\x65\x79\x49\x6e\146\157";
        $tA = $Lc->query($BJ, $li);
        $TG = $tA->item(0);
        if ($TG) {
            goto B_;
        }
        return $kb;
        B_:
        foreach ($TG->childNodes as $NW) {
            switch ($NW->localName) {
                case "\x4b\145\171\116\141\x6d\x65":
                    if (empty($kb)) {
                        goto o3;
                    }
                    $kb->name = $NW->nodeValue;
                    o3:
                    goto Yo;
                case "\x4b\145\x79\126\141\154\165\145":
                    foreach ($NW->childNodes as $BO) {
                        switch ($BO->localName) {
                            case "\104\123\x41\x4b\145\171\126\141\x6c\x75\145":
                                throw new Exception("\x44\123\x41\113\145\x79\126\141\154\165\x65\x20\x63\x75\x72\x72\x65\156\164\x6c\171\40\x6e\157\x74\40\x73\165\160\x70\x6f\x72\164\x65\x64");
                            case "\122\123\x41\x4b\145\171\126\x61\154\165\145":
                                $VS = null;
                                $ZT = null;
                                if (!($G1 = $BO->getElementsByTagName("\115\157\x64\165\x6c\x75\163")->item(0))) {
                                    goto ME;
                                }
                                $VS = base64_decode($G1->nodeValue);
                                ME:
                                if (!($D8 = $BO->getElementsByTagName("\105\x78\160\x6f\x6e\x65\156\x74")->item(0))) {
                                    goto Li;
                                }
                                $ZT = base64_decode($D8->nodeValue);
                                Li:
                                if (!(empty($VS) || empty($ZT))) {
                                    goto IH;
                                }
                                throw new Exception("\115\x69\163\x73\x69\156\147\40\115\157\x64\x75\x6c\x75\163\x20\157\162\40\105\170\x70\x6f\x6e\145\x6e\x74");
                                IH:
                                $fI = XMLSecurityKey::convertRSA($VS, $ZT);
                                $kb->loadKey($fI);
                                goto Er;
                        }
                        B8:
                        Er:
                        GS:
                    }
                    C0:
                    goto Yo;
                case "\122\145\x74\x72\151\x65\166\x61\x6c\x4d\x65\x74\x68\x6f\144":
                    $i9 = $NW->getAttribute("\124\171\x70\145");
                    if (!($i9 !== "\x68\x74\164\160\x3a\x2f\57\x77\167\167\56\167\x33\x2e\x6f\x72\x67\x2f\62\x30\x30\61\57\x30\64\57\170\155\154\145\156\x63\43\x45\x6e\x63\162\171\x70\164\145\144\x4b\x65\x79")) {
                        goto mu;
                    }
                    goto Yo;
                    mu:
                    $Rs = $NW->getAttribute("\125\122\x49");
                    if (!($Rs[0] !== "\x23")) {
                        goto mK;
                    }
                    goto Yo;
                    mK:
                    $Zy = substr($Rs, 1);
                    $BJ = "\57\x2f\x78\155\x6c\163\x65\x63\x65\x6e\x63\72\x45\156\x63\162\x79\x70\x74\x65\144\x4b\x65\x79\x5b\100\x49\x64\75\47{$Zy}\x27\x5d";
                    $Fs = $Lc->query($BJ)->item(0);
                    if ($Fs) {
                        goto JJ;
                    }
                    throw new Exception("\125\x6e\141\142\154\145\x20\164\x6f\40\154\157\x63\x61\164\x65\x20\x45\x6e\143\x72\x79\x70\x74\145\144\x4b\145\x79\40\167\151\164\150\40\x40\x49\144\75\47{$Zy}\47\56");
                    JJ:
                    return XMLSecurityKey::fromEncryptedKeyElement($Fs);
                case "\x45\x6e\x63\x72\171\x70\164\x65\x64\x4b\x65\171":
                    return XMLSecurityKey::fromEncryptedKeyElement($NW);
                case "\130\x35\60\x39\104\141\164\x61":
                    if (!($wM = $NW->getElementsByTagName("\130\x35\x30\71\x43\145\x72\x74\151\x66\x69\x63\141\x74\145"))) {
                        goto yj;
                    }
                    if (!($wM->length > 0)) {
                        goto wm;
                    }
                    $eR = $wM->item(0)->textContent;
                    $eR = str_replace(array("\15", "\xa", "\40"), '', $eR);
                    $eR = "\55\55\55\x2d\x2d\102\105\x47\111\116\x20\x43\x45\x52\124\x49\x46\x49\x43\101\x54\x45\x2d\x2d\55\x2d\55\xa" . chunk_split($eR, 64, "\12") . "\x2d\55\55\x2d\x2d\105\x4e\x44\x20\x43\x45\122\124\111\x46\x49\x43\101\x54\x45\55\55\x2d\x2d\55\12";
                    $kb->loadKey($eR, false, true);
                    wm:
                    yj:
                    goto Yo;
            }
            Su:
            Yo:
            jf:
        }
        pt:
        return $kb;
    }
    public function locateKeyInfo($kb = null, $li = null)
    {
        if (!empty($li)) {
            goto lt;
        }
        $li = $this->rawNode;
        lt:
        return self::staticLocateKeyInfo($kb, $li);
    }
}
