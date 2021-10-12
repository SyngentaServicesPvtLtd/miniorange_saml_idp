<?php


include_once "\x49\104\120\125\164\x69\x6c\151\164\151\145\163\56\x70\x68\160";
class GenerateResponse
{
    private $xml;
    private $acsUrl;
    private $issuer;
    private $audience;
    private $username;
    private $email;
    private $name_id_attr;
    private $name_id_attr_format;
    private $mo_idp_response_signed;
    private $mo_idp_assertion_signed;
    private $mo_idp_encrypted_assertion;
    private $mo_idp_cert_encrypt;
    private $encryptionKey;
    private $attributes;
    private $inResponseTo;
    private $subject;
    function __construct($ZK, $Zs, $I8, $Q9, $hO, $uQ = null, $o_ = null, $QY = null, $MU = null, $nz = null, $gX = array(), $pl = '', $e3 = null)
    {
        $this->xml = new DOMDocument("\x31\x2e\x30", "\165\x74\x66\55\70");
        $this->acsUrl = $I8;
        $this->issuer = $Q9;
        $this->audience = $hO;
        $this->email = $ZK;
        $this->username = $Zs;
        $this->name_id_attr = $uQ;
        $this->name_id_attr_format = $pl;
        $this->mo_idp_response_signed = $o_;
        $this->mo_idp_assertion_signed = $QY;
        $this->mo_idp_encrypted_assertion = $MU;
        $this->mo_idp_cert_encrypt = $nz;
        $this->attributes = $gX;
        $this->inResponseTo = $e3;
    }
    function createSamlResponse()
    {
        $this->licenseCheck();
        $YW = $this->getResponseParams();
        $ps = $this->createResponseElement($YW);
        $this->xml->appendChild($ps);
        $Q9 = $this->buildIssuer();
        $ps->appendChild($Q9);
        $Vl = $this->buildStatus();
        $ps->appendChild($Vl);
        $vO = $this->buildStatusCode();
        $Vl->appendChild($vO);
        $Jr = $this->buildAssertion($YW);
        $ps->appendChild($Jr);
        $Au = '';
        $Au = variable_get("\x6d\151\x6e\x69\157\x72\x61\156\x67\145\137\163\141\155\x6c\x5f\151\144\160\137\x70\x72\151\166\141\164\x65\137\143\145\x72\164\151\146\x69\x63\x61\164\145");
        if (!$this->mo_idp_assertion_signed) {
            goto E0;
        }
        if (!empty($Au)) {
            goto qf;
        }
        $f6 = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . "\x72\145\163\x6f\x75\162\x63\145\163" . DIRECTORY_SEPARATOR . "\151\144\160\x2d\x73\151\147\156\151\156\x67\56\x6b\145\x79";
        goto kt;
        qf:
        $f6 = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . "\162\x65\163\x6f\x75\162\x63\145\163" . DIRECTORY_SEPARATOR . "\x43\165\x73\x74\x6f\155\x5f\x50\x72\x69\166\141\164\x65\x5f\103\x65\x72\x74\x69\x66\151\143\141\164\145\x2e\153\x65\x79";
        kt:
        $this->signNode($f6, $Jr, $this->subject, $YW);
        E0:
        if (!$this->mo_idp_encrypted_assertion) {
            goto rS;
        }
        $yD = $this->buildEncryptedAssertion($Jr);
        $ps->removeChild($Jr);
        $ps->appendChild($yD);
        rS:
        if (!$this->mo_idp_response_signed) {
            goto b5;
        }
        if (!empty($Au)) {
            goto D2;
        }
        $f6 = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . "\x72\x65\x73\x6f\165\162\x63\x65\163" . DIRECTORY_SEPARATOR . "\x69\x64\x70\x2d\163\151\147\x6e\151\x6e\x67\x2e\153\x65\171";
        goto hh;
        D2:
        $f6 = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . "\162\145\163\x6f\x75\x72\143\145\163" . DIRECTORY_SEPARATOR . "\103\x75\x73\x74\x6f\x6d\x5f\x50\162\x69\166\x61\164\x65\x5f\x43\x65\162\x74\151\x66\x69\143\141\164\x65\x2e\x6b\x65\171";
        hh:
        $this->signNode($f6, $ps, $Vl, $YW);
        b5:
        $Jq = $this->xml->saveXML();
        return $Jq;
    }
    public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }
    public function setEncryptionKey(XMLSecurityKey $BW = NULL)
    {
        $this->encryptionKey = $BW;
    }
    function getResponseParams()
    {
        $YW = array();
        $wQ = time();
        $YW["\111\163\x73\x75\x65\111\x6e\x73\x74\x61\x6e\x74"] = str_replace("\53\60\x30\72\60\x30", "\132", gmdate("\143", $wQ));
        $YW["\x4e\x6f\164\x4f\x6e\x4f\162\x41\x66\164\x65\x72"] = str_replace("\x2b\60\x30\x3a\x30\60", "\x5a", gmdate("\143", $wQ + 300));
        $YW["\116\157\x74\102\x65\x66\x6f\x72\x65"] = str_replace("\x2b\60\x30\72\x30\x30", "\132", gmdate("\x63", $wQ - 30));
        $YW["\101\x75\x74\150\156\111\156\x73\164\141\x6e\164"] = str_replace("\x2b\x30\x30\72\60\60", "\x5a", gmdate("\x63", $wQ - 120));
        $YW["\123\x65\x73\x73\151\x6f\x6e\x4e\157\164\117\156\x4f\162\101\146\x74\145\x72"] = str_replace("\x2b\x30\x30\72\60\60", "\x5a", gmdate("\143", $wQ + 3600 * 8));
        $YW["\x49\104"] = $this->generateUniqueID(40);
        $YW["\x41\163\163\145\162\164\x49\x44"] = $this->generateUniqueID(40);
        $YW["\x49\163\163\165\145\162"] = $this->issuer;
        $zo = '';
        $zo = variable_get("\155\x69\156\x69\x6f\162\141\x6e\x67\x65\x5f\163\x61\155\x6c\137\151\144\x70\x5f\x70\x75\x62\154\x5f\x63\x65\162\164\151\146\x69\x63\141\164\145");
        if ($zo != '') {
            goto uw;
        }
        $N5 = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . "\x72\145\x73\157\165\162\143\145\163" . DIRECTORY_SEPARATOR . "\x69\144\x70\x2d\163\151\147\156\x69\156\x67\56\143\x72\x74";
        goto VY;
        uw:
        $N5 = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . "\x72\145\163\x6f\165\x72\143\145\x73" . DIRECTORY_SEPARATOR . "\103\165\x73\x74\157\155\x5f\120\165\x62\x6c\151\143\137\103\x65\x72\x74\x69\146\151\143\x61\x74\x65\x2e\143\x72\x74";
        VY:
        $qX = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array("\x74\171\x70\x65" => "\x70\x75\x62\154\151\143"));
        $qX->loadKey($N5, TRUE, TRUE);
        $YW["\x78\x35\60\71"] = $qX->getX509Certificate();
        $YW["\x41\164\164\x72\x69\x62\x75\x74\145\163"] = $this->attributes;
        return $YW;
    }
    function createResponseElement($YW)
    {
        $ps = $this->xml->createElementNS("\165\162\x6e\x3a\157\141\x73\x69\163\x3a\156\141\155\x65\x73\72\x74\x63\72\x53\101\x4d\114\72\x32\56\x30\72\x70\162\157\x74\x6f\x63\x6f\x6c", "\163\141\x6d\154\x70\x3a\x52\145\x73\160\157\x6e\x73\x65");
        $ps->setAttribute("\x49\104", $YW["\111\104"]);
        $ps->setAttribute("\126\x65\x72\163\x69\x6f\x6e", "\x32\x2e\60");
        $ps->setAttribute("\111\163\x73\165\145\111\x6e\x73\164\x61\x6e\164", $YW["\x49\x73\163\165\x65\x49\x6e\163\164\x61\x6e\x74"]);
        $ps->setAttribute("\104\145\163\164\151\156\x61\164\x69\x6f\156", $this->acsUrl);
        if (!(isset($this->inResponseTo) && !is_null($this->inResponseTo))) {
            goto Cc;
        }
        $ps->setAttribute("\111\156\122\145\163\160\x6f\156\163\x65\124\157", $this->inResponseTo);
        Cc:
        return $ps;
    }
    function buildIssuer()
    {
        $Q9 = $this->xml->createElementNS("\165\162\x6e\72\x6f\x61\163\x69\x73\72\x6e\141\x6d\x65\x73\72\164\143\x3a\123\101\115\x4c\72\62\x2e\60\72\141\163\163\145\x72\164\x69\x6f\x6e", "\x73\x61\155\x6c\x3a\x49\x73\163\165\145\162", $this->issuer);
        return $Q9;
    }
    function buildStatus()
    {
        $Vl = $this->xml->createElementNS("\x75\162\x6e\72\157\x61\x73\151\163\x3a\156\141\155\145\x73\72\164\143\x3a\123\101\x4d\114\72\x32\x2e\60\72\160\162\157\x74\157\143\157\154", "\x73\141\155\154\x70\x3a\x53\164\141\164\x75\x73");
        return $Vl;
    }
    function buildStatusCode()
    {
        $vO = $this->xml->createElementNS("\x75\162\156\72\157\x61\x73\x69\163\72\156\141\x6d\x65\163\x3a\164\x63\x3a\123\x41\x4d\114\72\x32\x2e\x30\x3a\x70\x72\x6f\x74\x6f\x63\x6f\154", "\x73\141\155\x6c\x70\x3a\123\x74\141\164\165\x73\x43\157\x64\145");
        $vO->setAttribute("\x56\x61\x6c\165\x65", "\x75\162\156\x3a\x6f\x61\x73\151\x73\x3a\156\141\x6d\145\x73\x3a\x74\143\72\123\101\x4d\x4c\x3a\62\x2e\x30\72\x73\x74\141\164\x75\x73\x3a\x53\165\x63\143\145\x73\163");
        return $vO;
    }
    function buildAssertion($YW)
    {
        $Jr = $this->xml->createElementNS("\165\x72\x6e\72\x6f\141\163\x69\x73\72\156\141\155\145\163\72\x74\143\72\x53\x41\115\x4c\x3a\x32\56\60\x3a\x61\163\x73\x65\x72\164\x69\x6f\156", "\x73\x61\155\154\72\x41\x73\163\145\x72\164\151\157\156");
        $Jr->setAttribute("\x49\104", $YW["\x41\x73\163\145\x72\x74\111\x44"]);
        $Jr->setAttribute("\111\x73\x73\x75\145\111\156\163\x74\141\156\164", $YW["\x49\163\x73\x75\145\x49\x6e\x73\x74\x61\x6e\164"]);
        $Jr->setAttribute("\x56\145\x72\163\x69\157\156", "\62\x2e\x30");
        $Q9 = $this->buildIssuer($YW);
        $Jr->appendChild($Q9);
        $lY = $this->buildSubject($YW);
        $this->subject = $lY;
        $Jr->appendChild($lY);
        $TC = $this->buildCondition($YW);
        $Jr->appendChild($TC);
        $O1 = $this->buildAuthnStatement($YW);
        $Jr->appendChild($O1);
        $gX = $YW["\x41\x74\x74\162\151\142\165\x74\145\x73"];
        if (empty($gX)) {
            goto EE;
        }
        $VP = $this->buildAttrStatement($YW);
        $Jr->appendChild($VP);
        EE:
        return $Jr;
    }
    function buildSubject($YW)
    {
        $lY = $this->xml->createElement("\163\x61\x6d\x6c\x3a\x53\165\142\152\145\143\164");
        $Bg = $this->buildNameIdentifier();
        $lY->appendChild($Bg);
        $k9 = $this->buildSubjectConfirmation($YW);
        $lY->appendChild($k9);
        return $lY;
    }
    function buildNameIdentifier()
    {
        if ($this->name_id_attr === "\x65\x6d\x61\x69\154\101\x64\x64\162\x65\163\163") {
            goto er;
        }
        $Bg = $this->xml->createElement("\x73\141\155\x6c\72\116\141\x6d\x65\x49\x44", $this->username);
        goto AJ;
        er:
        $Bg = $this->xml->createElement("\x73\x61\155\154\72\116\x61\155\145\111\x44", $this->email);
        AJ:
        if (empty($this->name_id_attr_format)) {
            goto Yz;
        }
        $Bg->setAttribute("\106\157\x72\155\x61\164", "\x75\x72\x6e\x3a\x6f\x61\163\151\163\72\x6e\x61\x6d\145\x73\x3a\x74\x63\72\123\101\x4d\x4c\72" . $this->name_id_attr_format);
        goto DX;
        Yz:
        $Bg->setAttribute("\106\157\x72\x6d\x61\164", "\165\162\156\x3a\157\x61\x73\151\x73\72\x6e\x61\x6d\145\x73\x3a\x74\x63\x3a\123\x41\115\x4c\x3a\61\x2e\61\72\x6e\x61\155\x65\x69\x64\55\x66\x6f\x72\x6d\x61\164\x3a\x65\x6d\x61\x69\x6c\101\144\x64\x72\145\163\x73");
        DX:
        $Bg->setAttribute("\123\120\116\141\x6d\145\121\x75\x61\154\x69\x66\x69\145\x72", $this->audience);
        return $Bg;
    }
    function buildSubjectConfirmation($YW)
    {
        $k9 = $this->xml->createElement("\x73\x61\155\x6c\72\x53\165\x62\152\x65\143\x74\x43\157\156\x66\x69\x72\155\141\x74\x69\x6f\156");
        $k9->setAttribute("\115\x65\164\x68\x6f\144", "\x75\x72\156\72\x6f\141\163\x69\x73\72\x6e\x61\155\x65\163\72\164\143\72\x53\101\115\114\x3a\62\x2e\60\72\x63\x6d\72\x62\145\141\162\x65\x72");
        $k5 = $this->getSubjectConfirmationData($YW);
        $k9->appendChild($k5);
        return $k9;
    }
    function getSubjectConfirmationData($YW)
    {
        $k5 = $this->xml->createElement("\163\141\155\x6c\x3a\123\165\142\x6a\145\x63\x74\x43\157\x6e\x66\151\x72\x6d\x61\x74\x69\x6f\x6e\x44\x61\x74\141");
        $k5->setAttribute("\116\157\164\x4f\x6e\117\x72\x41\x66\164\x65\x72", $YW["\x4e\x6f\x74\x4f\156\x4f\162\x41\x66\164\145\162"]);
        $k5->setAttribute("\122\x65\x63\x69\160\x69\145\156\164", $this->acsUrl);
        if (!(isset($this->inResponseTo) && !is_null($this->inResponseTo))) {
            goto GN;
        }
        $k5->setAttribute("\111\x6e\122\145\x73\160\157\x6e\163\x65\x54\x6f", $this->inResponseTo);
        GN:
        return $k5;
    }
    function buildCondition($YW)
    {
        $TC = $this->xml->createElement("\163\x61\155\x6c\72\x43\x6f\156\144\151\x74\151\157\156\163");
        $TC->setAttribute("\x4e\x6f\x74\x42\145\146\157\162\145", $YW["\x4e\x6f\164\x42\145\x66\x6f\162\145"]);
        $TC->setAttribute("\x4e\157\x74\117\x6e\x4f\x72\101\146\164\x65\162", $YW["\116\x6f\164\117\x6e\117\162\x41\146\x74\x65\x72"]);
        $OA = $this->buildAudienceRestriction();
        $TC->appendChild($OA);
        return $TC;
    }
    function buildAudienceRestriction()
    {
        $OA = $this->xml->createElement("\x73\141\x6d\x6c\72\101\x75\x64\151\145\x6e\143\145\122\x65\163\x74\162\x69\143\x74\x69\x6f\156");
        $hO = $this->xml->createElement("\x73\141\155\x6c\x3a\x41\165\144\x69\145\156\x63\145", $this->audience);
        $OA->appendChild($hO);
        return $OA;
    }
    function buildAuthnStatement($YW)
    {
        $O1 = $this->xml->createElement("\163\x61\x6d\154\72\101\165\164\x68\x6e\123\164\141\164\145\x6d\145\x6e\x74");
        $O1->setAttribute("\101\x75\x74\150\x6e\111\156\163\164\141\156\164", $YW["\x41\x75\x74\x68\156\111\x6e\163\164\141\x6e\x74"]);
        $O1->setAttribute("\x53\145\163\x73\x69\x6f\x6e\x49\156\144\145\x78", "\137" . $this->generateUniqueID(30));
        $O1->setAttribute("\x53\x65\163\x73\151\157\x6e\116\157\164\x4f\x6e\117\162\x41\x66\164\145\162", $YW["\123\145\x73\x73\151\x6f\156\x4e\157\x74\117\156\x4f\x72\101\146\x74\145\x72"]);
        $PO = $this->xml->createElement("\163\141\155\x6c\x3a\101\165\x74\150\156\x43\x6f\x6e\164\145\170\x74");
        $be = $this->xml->createElement("\x73\141\x6d\x6c\72\x41\165\x74\150\x6e\x43\157\156\164\145\x78\x74\x43\154\x61\163\x73\122\x65\146", "\165\x72\156\72\157\x61\163\x69\163\x3a\156\141\x6d\145\163\x3a\x74\x63\x3a\x53\101\x4d\x4c\x3a\x32\56\60\x3a\x61\x63\x3a\x63\x6c\x61\x73\x73\145\163\72\120\x61\163\163\x77\x6f\x72\144\x50\x72\x6f\164\145\x63\164\x65\x64\124\x72\141\156\163\x70\x6f\162\164");
        $PO->appendChild($be);
        $O1->appendChild($PO);
        return $O1;
    }
    function buildAttrStatement($YW)
    {
        $VP = $this->xml->createElement("\163\141\x6d\154\x3a\101\164\164\x72\x69\142\x75\x74\145\x53\x74\141\x74\x65\155\x65\156\164");
        $vI = $YW["\x41\164\x74\x72\151\x62\x75\164\x65\163"];
        foreach ($vI as $BG => $Or) {
            $RV = $this->buildAttribute($BG, $Or);
            $VP->appendChild($RV);
            LW:
        }
        RE:
        return $VP;
    }
    function buildAttribute($qi, $Sn)
    {
        $RV = $this->xml->createElement("\163\141\x6d\154\x3a\101\164\164\162\151\x62\x75\164\145");
        $RV->setAttribute("\x4e\x61\x6d\145", $qi);
        $RV->setAttribute("\x4e\x61\x6d\x65\106\157\162\x6d\x61\x74", "\165\x72\156\x3a\x6f\141\x73\151\163\72\x6e\x61\x6d\145\x73\72\164\x63\72\123\101\x4d\x4c\72\x32\x2e\x30\x3a\141\164\x74\x72\156\x61\155\145\55\x66\157\x72\155\x61\x74\72\x62\x61\163\151\x63");
        if (is_array($Sn)) {
            goto SP;
        }
        $Fo = $this->xml->createElement("\163\141\x6d\154\x3a\x41\164\164\162\151\x62\165\x74\145\x56\x61\x6c\x75\145", $Sn);
        $RV->appendChild($Fo);
        goto fL;
        SP:
        foreach ($Sn as $gH => $xF) {
            $Fo = $this->xml->createElement("\x73\x61\x6d\154\x3a\101\x74\x74\x72\x69\142\165\164\x65\x56\141\154\x75\x65", $xF);
            $RV->appendChild($Fo);
            Hi:
        }
        Fg:
        fL:
        return $RV;
    }
    function buildEncryptedAssertion($Jr)
    {
        $yD = $this->xml->createElementNS("\x75\x72\x6e\72\157\x61\x73\x69\x73\72\x6e\x61\x6d\x65\163\x3a\x74\143\72\x53\101\115\114\72\62\x2e\x30\x3a\141\163\x73\145\x72\x74\x69\x6f\156", "\x73\141\155\154\160\x3a\x45\156\143\x72\x79\160\164\x65\144\x41\x73\x73\145\x72\x74\151\157\x6e");
        $WX = $this->buildEncryptedData($Jr);
        $yD->appendChild($yD->ownerDocument->importNode($WX, TRUE));
        return $yD;
    }
    function buildEncryptedData($Jr)
    {
        $WX = new XMLSecEnc();
        $WX->setNode($Jr);
        $WX->type = "\x68\x74\x74\x70\72\57\57\167\x77\x77\56\167\x33\x2e\157\x72\147\57\62\x30\60\61\x2f\x30\x34\57\x78\155\154\145\x6e\143\43\105\x6c\145\x6d\145\x6e\164";
        $OL = $this->mo_idp_cert_encrypt;
        $yx = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array("\164\x79\x70\x65" => "\x70\x75\142\x6c\151\143"));
        $yx->loadKey($OL, FALSE, TRUE);
        $this->setEncryptionKey($yx);
        $j0 = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $j0->generateSessionKey();
        $WX->encryptKey($this->encryptionKey, $j0);
        $Mw = $WX->encryptNode($j0, FALSE);
        return $Mw;
    }
    function signNode($f6, $li, $lY, $YW)
    {
        $qX = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array("\164\171\x70\x65" => "\x70\x72\x69\x76\x61\164\x65"));
        $qX->loadKey($f6, TRUE);
        $dd = new XMLSecurityDSig();
        $dd->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dd->addReferenceList(array($li), XMLSecurityDSig::SHA256, array("\150\164\x74\160\72\x2f\57\x77\x77\x77\56\167\x33\x2e\157\162\147\57\x32\x30\60\x30\x2f\60\x39\x2f\170\x6d\154\144\x73\151\x67\x23\145\x6e\x76\145\154\x6f\x70\145\x64\55\163\151\x67\x6e\x61\164\165\162\x65", XMLSecurityDSig::EXC_C14N), array("\x69\144\x5f\156\x61\155\145" => "\x49\104", "\157\x76\145\x72\167\x72\x69\x74\145" => false));
        $dd->sign($qX);
        $dd->add509Cert($YW["\170\x35\60\71"]);
        $dd->insertSignature($li, $lY);
    }
    function generateUniqueID($kA)
    {
        $gu = "\x61\x62\143\144\x65\146\60\61\x32\63\64\65\66\67\x38\71";
        $xU = strlen($gu);
        $iJ = '';
        $c0 = 0;
        cl:
        if (!($c0 < $kA)) {
            goto cz;
        }
        $iJ .= substr($gu, rand(0, 15), 1);
        os:
        $c0++;
        goto cl;
        cz:
        return "\141" . $iJ;
    }
    function licenseCheck()
    {
        global $base_url;
        $Bb = db_select("\155\x69\156\x69\157\x72\141\x6e\147\145\x5f\x73\x61\x6d\x6c\137\151\x64\160\137\165\x73\x65\162", "\x55\x73\145\x72\111\156")->fields("\125\163\145\162\x49\156")->condition("\x6d\x61\151\154", $this->email, "\75")->execute()->fetchAssoc();
        $TV = $Bb["\x55\163\145\162\111\156"];
        $V9 = new MiniorangeSAMLIdpCustomer(NULL, NULL, NULL, NULL);
        $oY = variable_get("\155\x69\x6e\151\x4f\162\x61\156\147\x65\137\x73\x61\x6d\154\x5f\x69\x64\x70\x5f\x75\163\x65\162\137\x63\x6f\x75\x6e\x74");
        $Ae = variable_get("\x6d\x69\156\x69\117\162\x61\156\x67\145\137\x73\x61\155\x6c\x5f\151\x64\160\137\154\x5f\145\x78\160");
        $h9 = variable_get("\165\145\x5f\143\x6f\x75\x6e\x74");
        $mU = variable_get("\x64\143\x68\145\143\x6b");
        $CL = variable_get("\x74\155\160\137\x65\x78\160");
        $Bb = db_select("\155\x69\156\x69\x6f\x72\x61\156\x67\145\137\x73\141\x6d\154\x5f\x69\144\x70\x5f\x75\x73\x65\162", "\x55\163\x65\x72\111\156")->fields("\125\163\145\x72\111\156")->condition("\x55\x73\x65\x72\x49\156", 1, "\75")->execute();
        $kt = $Bb->rowCount();
        $h1 = date("\x59\x2d\115\x2d\x64\40\50\154\51\40\x68\72\x69\72\163\141", $Ae);
        $W3 = $Ae - time();
        $BQ = (int) ($W3 / 60 / 60 / 24);
        if (time() > $Ae + 2592000) {
            goto qV;
        }
        if (time() >= $Ae - 2592000 && !variable_get("\155\x69\x6e\151\x6f\162\x61\156\147\x65\137\145\x78\x6c\151\x5f\164\150\151\162\164\x79\141\x62\143")) {
            goto R7;
        }
        if (time() >= $Ae - 1296000 && !variable_get("\155\151\156\x69\157\x72\x61\156\147\x65\x5f\x65\x78\x6c\x69\137\x66\151\146\164\x65\145\156\141\x62\143")) {
            goto gB;
        }
        if (time() >= $Ae - 432000 && !variable_get("\155\151\x6e\x69\x6f\x72\x61\x6e\x67\145\x5f\x65\170\x6c\151\x5f\146\151\x76\x65\x61\x62\x63")) {
            goto Oh;
        }
        if (time() >= $Ae && !variable_get("\155\x69\156\x69\x6f\162\x61\x6e\147\x65\x5f\145\170\x6c\151\x61\142\x63")) {
            goto BY;
        }
        if (!(time() >= $Ae + 1296000 && !variable_get("\155\x69\156\x69\157\x72\141\156\x67\145\137\147\162\x63\x5f\x66\x69\166\x65\141\x62\143"))) {
            goto Yd;
        }
        if (IDPUtilities::licensevalidity($Ae)) {
            goto Lu;
        }
        variable_set("\155\x69\156\151\x6f\162\141\156\147\145\137\x67\x72\143\x5f\146\151\166\x65\x61\x62\143", 1);
        IDPUtilities::dexdmid($h1);
        Lu:
        Yd:
        goto X7;
        BY:
        if (IDPUtilities::licensevalidity($Ae)) {
            goto EP;
        }
        variable_set("\155\x69\x6e\151\157\x72\x61\156\147\145\137\x65\170\154\151\x61\142\143", 1);
        IDPUtilities::limit($h1);
        EP:
        X7:
        goto Cg;
        Oh:
        if (IDPUtilities::licensevalidity($Ae)) {
            goto YC;
        }
        variable_set("\155\151\156\x69\x6f\162\141\156\x67\x65\x5f\145\x78\x6c\x69\x5f\146\151\166\x65\x61\142\x63", 1);
        IDPUtilities::dayleft($BQ);
        YC:
        Cg:
        goto Fl;
        gB:
        if (IDPUtilities::licensevalidity($Ae)) {
            goto ir;
        }
        variable_set("\x6d\x69\x6e\151\157\x72\141\x6e\x67\x65\x5f\x65\170\x6c\151\x5f\x66\151\146\x74\x65\145\156\x61\x62\x63", 1);
        IDPUtilities::dayleft($BQ);
        ir:
        Fl:
        goto t8;
        R7:
        if (IDPUtilities::licensevalidity($Ae)) {
            goto Rv;
        }
        variable_set("\155\x69\x6e\x69\x6f\x72\141\x6e\x67\145\x5f\x65\170\x6c\151\137\x74\150\x69\162\164\171\141\x62\143", 1);
        IDPUtilities::dayleft($BQ);
        Rv:
        t8:
        goto Ua;
        qV:
        if (IDPUtilities::licensevalidity($Ae)) {
            goto Tr;
        }
        IDPUtilities::dexdend($h1);
        $zO = db_update("\x6d\x69\x6e\151\x6f\x72\141\x6e\147\145\x5f\x73\x61\x6d\x6c\x5f\x69\x64\x70\137\165\x73\145\x72")->fields(array("\125\x73\145\162\111\156" => 0))->execute();
        IDPUtilities::freeLicenseKey();
        header("\114\157\x63\141\164\x69\157\x6e\x3a\40" . $base_url);
        Tr:
        Ua:
        if ($TV) {
            goto cF;
        }
        if ($kt >= $oY) {
            goto Jf;
        }
        $Bb = db_select("\155\x69\156\x69\157\x72\x61\x6e\x67\145\x5f\x73\141\155\x6c\x5f\x69\x64\160\137\x75\163\x65\162", "\x55\163\x65\162\x49\156")->fields("\125\x73\x65\x72\x49\156")->condition("\x6d\141\x69\154", $this->email, "\x3d")->execute();
        $ni = $Bb->rowCount();
        if ($ni > 0) {
            goto EG;
        }
        db_insert("\155\x69\156\151\x6f\x72\141\x6e\x67\145\x5f\163\141\155\x6c\x5f\151\x64\160\137\165\163\145\x72")->fields(array("\155\x61\151\x6c" => $this->email, "\x55\x73\145\162\111\x6e" => 1))->execute();
        goto Wt;
        EG:
        $zO = db_update("\x6d\x69\156\x69\x6f\162\141\156\x67\x65\x5f\x73\x61\x6d\154\x5f\151\x64\160\137\165\x73\145\x72")->fields(array("\125\x73\145\x72\x49\156" => 1))->condition("\x6d\141\151\154", $this->email, "\75")->execute();
        Wt:
        $kt = $kt + 1;
        $s_ = floor($oY * 0.8);
        $O2 = floor($oY * 0.9);
        if ($kt == $s_) {
            goto sQ;
        }
        if ($kt == $O2) {
            goto XD;
        }
        if ($oY - $kt == 10) {
            goto ou;
        }
        if (!($kt == $oY)) {
            goto e3;
        }
        if (IDPUtilities::checkupdate($oY)) {
            goto w9;
        }
        $mU = 0;
        variable_set("\x64\143\x68\x65\x63\x6b", $mU);
        variable_set("\x74\x6d\x70\x5f\x65\x78\x70", time() + 2592000);
        IDPUtilities::limitreach($oY, $kt);
        goto H6;
        w9:
        return;
        H6:
        e3:
        goto cM;
        ou:
        if (IDPUtilities::checkupdate($oY)) {
            goto ag;
        }
        IDPUtilities::tenuser($oY, $kt);
        goto lc;
        ag:
        return;
        lc:
        cM:
        goto iS;
        XD:
        if (IDPUtilities::checkupdate($oY)) {
            goto h9;
        }
        IDPUtilities::peruser(90, $oY);
        goto NS;
        h9:
        return;
        NS:
        iS:
        goto eL;
        sQ:
        IDPUtilities::peruser(80, $oY);
        eL:
        goto Wu;
        Jf:
        $Ej = abs($CL - time()) / 60 / 60 / 24;
        if (!($Ej != $mU)) {
            goto ib;
        }
        if (!IDPUtilities::checkupdate($oY)) {
            goto PJ;
        }
        variable_set("\x75\x65\x5f\143\157\165\x6e\164", 0);
        $Bb = db_select("\x6d\x69\x6e\151\x6f\162\x61\x6e\147\145\x5f\163\141\155\x6c\137\151\144\x70\137\165\x73\145\x72", "\x55\163\145\162\x49\156")->fields("\x55\163\x65\x72\x49\x6e")->condition("\x6d\x61\151\154", $this->email, "\75")->execute();
        $ni = $Bb->rowCount();
        if ($ni > 0) {
            goto h3;
        }
        db_insert("\155\x69\x6e\151\x6f\x72\141\x6e\x67\x65\137\x73\x61\x6d\154\137\x69\x64\x70\x5f\165\163\x65\x72")->fields(array("\155\141\x69\154" => $this->email, "\x55\x73\145\162\x49\x6e" => 1))->execute();
        goto B3;
        h3:
        $zO = db_update("\x6d\x69\156\x69\x6f\x72\x61\156\x67\145\137\x73\141\x6d\x6c\137\151\144\x70\137\x75\x73\x65\x72")->fields(array("\125\163\145\162\111\x6e" => 1))->condition("\x6d\x61\x69\154", $this->email, "\75")->execute();
        B3:
        PJ:
        variable_set("\144\x63\150\145\143\153", $Ej);
        ib:
        if (time() < $CL) {
            goto km;
        }
        if (!($h9 == 1)) {
            goto M2;
        }
        IDPUtilities::limitend($oY);
        $h9++;
        variable_set("\x75\x65\137\x63\x6f\x75\x6e\x74", $h9);
        M2:
        echo "\123\123\117\40\106\x61\x69\x6c\145\144\x2e\x20\115\141\x78\x69\155\x75\x6d\40\154\151\x6d\x69\164\40\162\145\x61\x63\150\145\144\x2e\40\120\x6c\x65\141\x73\145\x20\143\x6f\x6e\164\141\143\x74\40\171\x6f\x75\x72\40\x41\144\155\151\x6e\x69\163\x74\x72\x61\x74\x6f\162\40\x66\157\x72\x20\x6d\x6f\162\x65\x20\144\x65\x74\x61\151\x6c\x73\56";
        exit;
        goto Fb;
        km:
        if (!(time() > $CL - 1296000 && $h9 == 0)) {
            goto Dx;
        }
        IDPUtilities::limitmid($oY);
        $h9++;
        variable_set("\x75\x65\x5f\143\157\x75\156\164", $h9);
        Dx:
        return;
        Fb:
        Wu:
        goto FC;
        cF:
        return;
        FC:
    }
}
