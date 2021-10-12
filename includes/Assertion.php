<?php


include_once "\x49\x44\x50\125\164\151\154\151\x74\x69\145\163\x2e\160\x68\x70";
class SAML2_Assertion
{
    private $id;
    private $issueInstant;
    private $issuer;
    private $nameId;
    private $encryptedNameId;
    private $encryptedAttribute;
    private $encryptionKey;
    private $notBefore;
    private $notOnOrAfter;
    private $validAudiences;
    private $sessionNotOnOrAfter;
    private $sessionIndex;
    private $authnInstant;
    private $authnContextClassRef;
    private $authnContextDecl;
    private $authnContextDeclRef;
    private $AuthenticatingAuthority;
    private $attributes;
    private $nameFormat;
    private $signatureKey;
    private $certificates;
    private $signatureData;
    private $requiredEncAttributes;
    private $SubjectConfirmation;
    protected $wasSignedAtConstruction = FALSE;
    public function __construct(DOMElement $hB = NULL)
    {
        $this->id = IDPUtilities::generateId();
        $this->issueInstant = IDPUtilities::generateTimestamp();
        $this->issuer = '';
        $this->authnInstant = IDPUtilities::generateTimestamp();
        $this->attributes = array();
        $this->nameFormat = "\x75\162\x6e\x3a\x6f\x61\x73\151\163\72\x6e\141\x6d\x65\x73\x3a\164\143\x3a\x53\x41\115\114\72\61\56\x31\x3a\156\141\155\x65\x69\144\x2d\146\157\x72\155\x61\x74\x3a\x75\156\163\x70\x65\143\151\x66\151\x65\144";
        $this->certificates = array();
        $this->AuthenticatingAuthority = array();
        $this->SubjectConfirmation = array();
        if (!($hB === NULL)) {
            goto pv;
        }
        return;
        pv:
        if (!($hB->localName === "\x45\x6e\x63\x72\x79\160\x74\x65\x64\101\163\x73\145\162\x74\151\157\x6e")) {
            goto lU;
        }
        $qB = IDPUtilities::xpQuery($hB, "\x2e\x2f\170\145\x6e\x63\x3a\105\x6e\143\x72\171\x70\164\x65\144\104\x61\164\141");
        $sH = IDPUtilities::xpQuery($hB, "\x2e\57\x78\145\x6e\143\72\x45\x6e\x63\162\171\x70\164\x65\x64\x44\x61\x74\141\57\x64\163\72\x4b\145\171\111\x6e\146\157\57\170\x65\156\143\x3a\105\156\143\162\171\160\164\145\x64\x4b\145\x79");
        $kG = '';
        if (empty($sH)) {
            goto kx;
        }
        $kG = $sH[0]->firstChild->getAttribute("\101\x6c\x67\x6f\162\x69\x74\150\155");
        goto ai;
        kx:
        $sH = IDPUtilities::xpQuery($hB, "\56\57\x78\145\x6e\143\72\x45\156\143\x72\171\x70\x74\x65\144\113\x65\x79\x2f\170\x65\x6e\x63\72\105\x6e\x63\162\171\160\164\x69\157\x6e\x4d\x65\x74\150\x6f\144");
        $kG = $sH[0]->getAttribute("\x41\154\147\x6f\162\x69\164\x68\155");
        ai:
        $IV = IDPUtilities::getEncryptionAlgorithm($kG);
        if (count($qB) === 0) {
            goto FR;
        }
        if (count($qB) > 1) {
            goto OC;
        }
        goto tw;
        FR:
        throw new Exception("\115\x69\163\x73\151\x6e\147\40\145\x6e\x63\162\x79\160\x74\x65\144\x20\x64\x61\164\x61\40\151\156\40\74\x73\x61\x6d\x6c\72\x45\x6e\x63\x72\171\160\164\145\144\101\x73\163\x65\162\164\x69\157\x6e\x3e\x2e");
        goto tw;
        OC:
        throw new Exception("\x4d\157\x72\145\x20\164\x68\x61\x6e\x20\157\x6e\145\40\x65\x6e\x63\162\171\160\x74\145\144\40\144\141\164\141\40\145\154\145\155\145\x6e\164\40\151\156\40\x3c\x73\141\x6d\x6c\x3a\105\x6e\143\162\171\x70\164\145\x64\x41\163\x73\x65\162\164\x69\157\156\76\56");
        tw:
        $gH = new XMLSecurityKey($IV, array("\x74\171\160\x65" => "\x70\x72\x69\x76\141\x74\145"));
        $zi = plugin_dir_path(__FILE__) . "\162\145\x73\x6f\165\x72\143\145\163" . DIRECTORY_SEPARATOR . "\x73\x70\x2d\153\145\x79\x2e\x6b\x65\x79";
        $gH->loadKey($zi, TRUE);
        $ZC = new XMLSecurityKey($IV, array("\164\x79\160\x65" => "\160\162\x69\x76\x61\x74\145"));
        $cS = plugin_dir_path(__FILE__) . "\162\145\163\157\x75\162\x63\145\163" . DIRECTORY_SEPARATOR . "\x6d\151\x6e\x69\x6f\x72\141\156\147\145\x5f\x73\160\137\x70\162\x69\166\x5f\153\x65\x79\56\x6b\x65\171";
        $ZC->loadKey($cS, TRUE);
        $rf = array();
        $hB = IDPUtilities::decryptElement($qB[0], $gH, $rf, $ZC);
        lU:
        if ($hB->hasAttribute("\x49\104")) {
            goto yy;
        }
        throw new Exception("\x4d\151\163\163\151\x6e\x67\40\x49\x44\40\x61\x74\x74\x72\x69\x62\x75\164\x65\x20\157\x6e\x20\123\x41\115\114\40\141\163\163\x65\162\164\x69\x6f\x6e\56");
        yy:
        $this->id = $hB->getAttribute("\111\104");
        if (!($hB->getAttribute("\x56\145\162\x73\x69\x6f\156") !== "\62\x2e\60")) {
            goto OH;
        }
        throw new Exception("\125\156\x73\165\x70\x70\157\162\164\145\144\40\166\145\x72\163\151\x6f\x6e\x3a\x20" . $hB->getAttribute("\126\x65\162\x73\x69\x6f\x6e"));
        OH:
        $this->issueInstant = IDPUtilities::xsDateTimeToTimestamp($hB->getAttribute("\111\x73\x73\165\145\111\x6e\163\164\x61\156\x74"));
        $Q9 = IDPUtilities::xpQuery($hB, "\56\x2f\x73\x61\x6d\154\137\x61\163\x73\145\x72\x74\x69\157\x6e\x3a\x49\x73\163\165\x65\162");
        if (!empty($Q9)) {
            goto ji;
        }
        throw new Exception("\115\151\163\163\x69\x6e\x67\40\74\x73\x61\x6d\x6c\x3a\x49\163\163\x75\x65\162\x3e\x20\151\156\40\x61\x73\x73\x65\162\164\x69\157\156\56");
        ji:
        $this->issuer = trim($Q9[0]->textContent);
        $this->parseConditions($hB);
        $this->parseAuthnStatement($hB);
        $this->parseAttributes($hB);
        $this->parseEncryptedAttributes($hB);
        $this->parseSignature($hB);
        $this->parseSubject($hB);
    }
    private function parseSubject(DOMElement $hB)
    {
        $lY = IDPUtilities::xpQuery($hB, "\56\57\x73\x61\x6d\x6c\137\141\163\x73\145\x72\x74\x69\x6f\156\x3a\123\165\x62\x6a\x65\x63\x74");
        if (empty($lY)) {
            goto Yb;
        }
        if (count($lY) > 1) {
            goto Yv;
        }
        goto wC;
        Yb:
        return;
        goto wC;
        Yv:
        throw new Exception("\x4d\157\162\145\40\x74\x68\x61\x6e\x20\157\x6e\x65\x20\74\163\x61\155\x6c\72\x53\165\x62\152\145\143\164\76\40\151\156\x20\74\163\x61\155\154\72\101\x73\x73\145\162\x74\151\157\156\76\x2e");
        wC:
        $lY = $lY[0];
        $VO = IDPUtilities::xpQuery($lY, "\56\x2f\x73\x61\x6d\x6c\x5f\x61\x73\x73\145\x72\x74\x69\157\x6e\72\x4e\141\x6d\145\111\x44\x20\x7c\40\x2e\57\163\141\x6d\154\x5f\x61\163\x73\x65\x72\x74\x69\x6f\x6e\x3a\x45\x6e\143\162\171\160\164\145\144\x49\104\57\x78\x65\156\x63\x3a\x45\x6e\143\x72\171\x70\164\x65\x64\x44\x61\x74\x61");
        if (empty($VO)) {
            goto P9;
        }
        if (count($VO) > 1) {
            goto XP;
        }
        goto Mx;
        P9:
        throw new Exception("\115\x69\163\163\151\156\147\x20\74\x73\x61\155\154\x3a\116\x61\x6d\x65\x49\x44\x3e\x20\x6f\x72\40\x3c\x73\x61\x6d\154\x3a\x45\x6e\x63\x72\171\x70\164\x65\144\111\104\76\x20\151\x6e\x20\74\x73\x61\155\154\x3a\123\165\x62\152\x65\143\164\x3e\56");
        goto Mx;
        XP:
        throw new Exception("\x4d\157\x72\145\x20\164\x68\141\x6e\40\x6f\156\x65\40\x3c\x73\141\x6d\154\x3a\116\x61\x6d\x65\x49\x44\x3e\40\x6f\x72\40\74\x73\141\155\x6c\x3a\x45\156\x63\162\171\160\x74\x65\x64\104\x3e\40\151\x6e\x20\x3c\163\x61\155\x6c\x3a\x53\x75\142\x6a\x65\x63\x74\76\56");
        Mx:
        $VO = $VO[0];
        if ($VO->localName === "\105\x6e\143\162\x79\160\x74\x65\144\104\141\164\x61") {
            goto Lc;
        }
        $this->nameId = IDPUtilities::parseNameId($VO);
        goto VL;
        Lc:
        $this->encryptedNameId = $VO;
        VL:
    }
    private function parseConditions(DOMElement $hB)
    {
        $ow = IDPUtilities::xpQuery($hB, "\x2e\x2f\163\x61\x6d\154\137\x61\x73\163\145\x72\164\x69\x6f\x6e\72\x43\157\x6e\144\x69\x74\151\x6f\156\163");
        if (empty($ow)) {
            goto vj;
        }
        if (count($ow) > 1) {
            goto Sz;
        }
        goto MC;
        vj:
        return;
        goto MC;
        Sz:
        throw new Exception("\115\157\x72\145\40\164\x68\141\x6e\40\x6f\156\145\40\74\163\x61\x6d\x6c\72\x43\x6f\x6e\x64\151\164\x69\157\156\163\76\40\x69\x6e\40\x3c\x73\x61\155\154\x3a\101\163\x73\x65\x72\x74\151\157\156\x3e\x2e");
        MC:
        $ow = $ow[0];
        if (!$ow->hasAttribute("\x4e\x6f\x74\x42\145\146\x6f\162\x65")) {
            goto Yr;
        }
        $VF = IDPUtilities::xsDateTimeToTimestamp($ow->getAttribute("\116\x6f\164\x42\x65\x66\157\162\145"));
        if (!($this->notBefore === NULL || $this->notBefore < $VF)) {
            goto H5;
        }
        $this->notBefore = $VF;
        H5:
        Yr:
        if (!$ow->hasAttribute("\x4e\157\164\117\156\117\162\x41\146\164\145\x72")) {
            goto po;
        }
        $nJ = IDPUtilities::xsDateTimeToTimestamp($ow->getAttribute("\116\157\164\x4f\x6e\x4f\162\x41\146\x74\x65\162"));
        if (!($this->notOnOrAfter === NULL || $this->notOnOrAfter > $nJ)) {
            goto L1;
        }
        $this->notOnOrAfter = $nJ;
        L1:
        po:
        $li = $ow->firstChild;
        QV:
        if (!($li !== NULL)) {
            goto Qb;
        }
        if (!$li instanceof DOMText) {
            goto fX;
        }
        goto N2;
        fX:
        if (!($li->namespaceURI !== "\x75\162\x6e\x3a\x6f\141\163\x69\x73\72\x6e\141\155\145\163\x3a\x74\143\72\x53\x41\x4d\x4c\72\x32\x2e\60\x3a\x61\x73\163\x65\162\x74\x69\x6f\x6e")) {
            goto q_;
        }
        throw new Exception("\125\x6e\x6b\156\x6f\x77\156\40\x6e\x61\x6d\145\163\160\141\143\145\40\x6f\146\40\x63\x6f\x6e\x64\x69\x74\151\157\x6e\x3a\x20" . var_export($li->namespaceURI, TRUE));
        q_:
        switch ($li->localName) {
            case "\x41\165\144\x69\x65\156\143\x65\122\145\163\164\x72\151\x63\x74\151\157\x6e":
                $H7 = IDPUtilities::extractStrings($li, "\165\x72\x6e\72\x6f\141\163\151\x73\72\x6e\141\x6d\145\x73\72\x74\x63\x3a\123\x41\115\114\x3a\62\x2e\60\x3a\x61\x73\x73\145\x72\x74\x69\157\156", "\x41\165\144\151\x65\x6e\x63\145");
                if ($this->validAudiences === NULL) {
                    goto DV;
                }
                $this->validAudiences = array_intersect($this->validAudiences, $H7);
                goto i4;
                DV:
                $this->validAudiences = $H7;
                i4:
                goto sw;
            case "\117\156\145\124\x69\155\x65\x55\163\x65":
                goto sw;
            case "\x50\x72\x6f\170\171\x52\145\x73\164\x72\151\x63\164\x69\157\156":
                goto sw;
            default:
                throw new Exception("\125\x6e\x6b\x6e\x6f\x77\156\x20\143\157\156\144\151\164\151\x6f\x6e\x3a\40" . var_export($li->localName, TRUE));
        }
        u_:
        sw:
        N2:
        $li = $li->nextSibling;
        goto QV;
        Qb:
    }
    private function parseAuthnStatement(DOMElement $hB)
    {
        $Mx = IDPUtilities::xpQuery($hB, "\56\x2f\x73\141\x6d\x6c\137\x61\x73\163\x65\x72\164\151\157\x6e\72\101\x75\164\150\156\123\164\x61\164\x65\x6d\145\156\x74");
        if (empty($Mx)) {
            goto d6;
        }
        if (count($Mx) > 1) {
            goto Cl;
        }
        goto dV;
        d6:
        $this->authnInstant = NULL;
        return;
        goto dV;
        Cl:
        throw new Exception("\115\157\x72\145\x20\x74\x68\x61\164\40\157\156\x65\x20\74\x73\x61\155\154\72\101\165\164\x68\x6e\x53\164\x61\164\145\x6d\145\156\164\x3e\40\151\x6e\40\74\x73\x61\155\154\72\x41\x73\x73\x65\x72\164\x69\157\156\x3e\x20\156\157\x74\40\163\x75\160\160\157\x72\164\x65\x64\56");
        dV:
        $Pr = $Mx[0];
        if ($Pr->hasAttribute("\x41\165\x74\x68\156\x49\x6e\163\164\141\x6e\x74")) {
            goto z0;
        }
        throw new Exception("\x4d\151\163\x73\x69\156\147\40\162\145\161\x75\x69\162\145\x64\x20\101\x75\x74\150\x6e\111\156\163\164\x61\156\x74\x20\141\x74\x74\162\x69\142\165\164\145\x20\157\156\x20\74\x73\141\x6d\x6c\72\101\165\164\x68\x6e\x53\x74\x61\x74\145\155\x65\x6e\x74\x3e\x2e");
        z0:
        $this->authnInstant = IDPUtilities::xsDateTimeToTimestamp($Pr->getAttribute("\101\x75\164\x68\x6e\111\x6e\x73\x74\141\x6e\x74"));
        if (!$Pr->hasAttribute("\123\x65\x73\x73\151\x6f\156\116\157\x74\x4f\x6e\x4f\162\101\x66\x74\145\x72")) {
            goto q2;
        }
        $this->sessionNotOnOrAfter = IDPUtilities::xsDateTimeToTimestamp($Pr->getAttribute("\123\145\163\x73\x69\x6f\x6e\x4e\157\x74\x4f\x6e\117\x72\x41\x66\164\145\x72"));
        q2:
        if (!$Pr->hasAttribute("\123\x65\163\163\151\x6f\156\111\x6e\144\x65\x78")) {
            goto QZ;
        }
        $this->sessionIndex = $Pr->getAttribute("\123\145\x73\163\151\x6f\x6e\111\x6e\x64\145\x78");
        QZ:
        $this->parseAuthnContext($Pr);
    }
    private function parseAuthnContext(DOMElement $NI)
    {
        $bB = IDPUtilities::xpQuery($NI, "\x2e\x2f\163\141\x6d\x6c\137\x61\163\163\x65\162\x74\151\x6f\156\x3a\101\165\x74\150\156\103\x6f\156\164\145\x78\164");
        if (count($bB) > 1) {
            goto da;
        }
        if (empty($bB)) {
            goto EV;
        }
        goto U3;
        da:
        throw new Exception("\x4d\157\162\x65\x20\x74\150\x61\x6e\40\x6f\156\145\x20\x3c\163\141\x6d\x6c\72\101\165\164\150\x6e\x43\157\156\164\x65\170\x74\x3e\x20\151\156\x20\74\163\x61\155\x6c\x3a\101\x75\x74\150\156\123\164\x61\x74\145\155\145\x6e\164\x3e\56");
        goto U3;
        EV:
        throw new Exception("\115\x69\x73\163\x69\156\147\x20\x72\x65\161\x75\x69\162\145\144\x20\x3c\163\x61\x6d\x6c\x3a\x41\x75\x74\150\156\x43\x6f\156\164\x65\x78\164\x3e\x20\151\156\40\74\x73\x61\155\154\72\x41\165\x74\150\156\x53\x74\x61\164\145\155\x65\156\x74\76\x2e");
        U3:
        $J5 = $bB[0];
        $JF = IDPUtilities::xpQuery($J5, "\56\57\163\x61\155\x6c\x5f\141\163\x73\145\x72\x74\151\157\x6e\x3a\x41\x75\164\x68\156\103\x6f\156\164\x65\170\164\x44\145\143\x6c\x52\x65\x66");
        if (count($JF) > 1) {
            goto nj;
        }
        if (count($JF) === 1) {
            goto ot;
        }
        goto fY;
        nj:
        throw new Exception("\115\157\162\145\x20\x74\x68\x61\156\40\157\x6e\x65\x20\74\x73\141\x6d\154\x3a\101\165\164\x68\156\x43\x6f\x6e\x74\x65\x78\164\104\145\143\154\122\x65\146\x3e\40\x66\x6f\x75\156\x64\77");
        goto fY;
        ot:
        $this->setAuthnContextDeclRef(trim($JF[0]->textContent));
        fY:
        $A4 = IDPUtilities::xpQuery($J5, "\x2e\x2f\163\x61\x6d\154\x5f\x61\x73\163\145\x72\x74\151\157\x6e\72\101\165\x74\x68\156\103\x6f\156\164\145\x78\x74\104\x65\143\154");
        if (count($A4) > 1) {
            goto uk;
        }
        if (count($A4) === 1) {
            goto GK;
        }
        goto x8;
        uk:
        throw new Exception("\x4d\157\x72\x65\40\164\150\x61\156\40\157\156\145\x20\x3c\x73\x61\x6d\x6c\x3a\101\x75\164\150\156\x43\x6f\x6e\164\x65\x78\x74\104\145\x63\154\76\x20\x66\x6f\165\156\144\77");
        goto x8;
        GK:
        $this->setAuthnContextDecl(new SAML2_XML_Chunk($A4[0]));
        x8:
        $Xz = IDPUtilities::xpQuery($J5, "\x2e\x2f\x73\141\x6d\154\137\141\x73\163\x65\162\x74\151\157\156\x3a\x41\165\x74\150\x6e\103\x6f\156\164\x65\170\x74\x43\x6c\x61\163\x73\x52\145\146");
        if (count($Xz) > 1) {
            goto WR;
        }
        if (count($Xz) === 1) {
            goto Cf;
        }
        goto jO;
        WR:
        throw new Exception("\115\157\162\145\40\x74\x68\141\156\40\157\x6e\x65\40\x3c\163\141\x6d\x6c\x3a\101\x75\164\150\x6e\x43\157\156\164\145\170\164\x43\154\141\x73\x73\x52\145\146\76\40\151\156\x20\74\163\141\155\x6c\72\x41\165\164\x68\156\x43\x6f\156\164\145\170\x74\76\x2e");
        goto jO;
        Cf:
        $this->setAuthnContextClassRef(trim($Xz[0]->textContent));
        jO:
        if (!(empty($this->authnContextClassRef) && empty($this->authnContextDecl) && empty($this->authnContextDeclRef))) {
            goto zL;
        }
        throw new Exception("\115\151\163\x73\x69\x6e\x67\x20\145\151\x74\150\x65\x72\x20\74\x73\141\x6d\154\x3a\x41\165\164\150\156\103\157\x6e\x74\145\x78\164\x43\154\141\x73\x73\122\145\x66\x3e\40\x6f\162\40\x3c\x73\141\155\154\72\x41\x75\164\150\x6e\103\157\156\164\145\170\164\x44\x65\x63\x6c\122\145\x66\76\x20\157\162\x20\74\163\x61\x6d\x6c\72\101\165\164\150\x6e\103\157\156\164\x65\170\164\104\145\143\154\76");
        zL:
        $this->AuthenticatingAuthority = IDPUtilities::extractStrings($J5, "\165\162\156\x3a\x6f\141\x73\x69\x73\x3a\x6e\x61\x6d\145\x73\72\x74\x63\72\123\101\115\x4c\x3a\x32\56\60\x3a\x61\163\163\145\x72\164\151\x6f\156", "\101\x75\164\150\x65\x6e\x74\x69\143\x61\x74\151\156\x67\101\x75\164\x68\x6f\x72\151\164\171");
    }
    private function parseAttributes(DOMElement $hB)
    {
        $gU = TRUE;
        $gX = IDPUtilities::xpQuery($hB, "\x2e\57\x73\x61\155\x6c\137\141\163\163\x65\x72\164\151\x6f\156\x3a\101\x74\x74\x72\151\x62\x75\164\145\x53\164\x61\164\x65\x6d\145\x6e\164\57\163\141\x6d\x6c\137\x61\x73\163\x65\x72\x74\x69\157\x6e\72\x41\164\x74\162\151\x62\165\164\x65");
        foreach ($gX as $AV) {
            if ($AV->hasAttribute("\x4e\x61\x6d\145")) {
                goto hy;
            }
            throw new Exception("\115\x69\163\163\x69\156\x67\40\x6e\141\x6d\x65\40\157\156\x20\x3c\163\141\x6d\x6c\x3a\x41\x74\164\162\x69\142\x75\164\x65\76\x20\145\154\x65\x6d\145\x6e\x74\56");
            hy:
            $ci = $AV->getAttribute("\x4e\141\155\x65");
            if ($AV->hasAttribute("\x4e\141\155\145\x46\157\x72\155\x61\x74")) {
                goto We;
            }
            $od = "\165\x72\x6e\72\157\141\x73\x69\x73\72\156\x61\155\145\163\72\x74\x63\72\123\x41\115\x4c\72\61\56\61\72\x6e\x61\155\145\x69\x64\x2d\146\x6f\162\x6d\x61\164\x3a\x75\x6e\x73\x70\x65\143\151\146\151\x65\144";
            goto Lf;
            We:
            $od = $AV->getAttribute("\116\x61\x6d\145\x46\x6f\x72\x6d\x61\164");
            Lf:
            if ($gU) {
                goto kd;
            }
            if (!($this->nameFormat !== $od)) {
                goto of;
            }
            $this->nameFormat = "\165\x72\156\x3a\x6f\141\163\151\x73\x3a\x6e\141\155\145\163\x3a\x74\143\x3a\x53\x41\115\114\x3a\61\56\61\72\x6e\141\x6d\x65\151\144\55\146\x6f\x72\155\x61\164\72\165\156\163\x70\145\143\x69\x66\x69\145\144";
            of:
            goto Vi;
            kd:
            $this->nameFormat = $od;
            $gU = FALSE;
            Vi:
            if (array_key_exists($ci, $this->attributes)) {
                goto mj;
            }
            $this->attributes[$ci] = array();
            mj:
            $jO = IDPUtilities::xpQuery($AV, "\56\x2f\x73\x61\155\154\x5f\141\x73\x73\x65\x72\164\x69\157\x6e\x3a\x41\x74\164\162\x69\x62\165\164\145\x56\141\x6c\165\x65");
            foreach ($jO as $Or) {
                $this->attributes[$ci][] = trim($Or->textContent);
                fa:
            }
            fg:
            oE:
        }
        IS:
    }
    private function parseEncryptedAttributes(DOMElement $hB)
    {
        $this->encryptedAttribute = IDPUtilities::xpQuery($hB, "\56\x2f\x73\141\x6d\154\137\141\163\163\x65\162\x74\151\157\x6e\72\101\164\x74\x72\x69\142\x75\x74\x65\x53\x74\141\164\x65\x6d\x65\x6e\x74\57\163\141\x6d\x6c\x5f\x61\x73\163\x65\162\x74\151\157\x6e\72\x45\x6e\143\162\171\x70\164\145\144\x41\x74\164\x72\x69\x62\165\x74\145");
    }
    private function parseSignature(DOMElement $hB)
    {
        $Xd = IDPUtilities::validateElement($hB);
        if (!($Xd !== FALSE)) {
            goto i5;
        }
        $this->wasSignedAtConstruction = TRUE;
        $this->certificates = $Xd["\x43\x65\x72\x74\151\146\x69\143\141\x74\145\x73"];
        $this->signatureData = $Xd;
        i5:
    }
    public function validate(XMLSecurityKey $gH)
    {
        if (!($this->signatureData === NULL)) {
            goto Xd;
        }
        return FALSE;
        Xd:
        IDPUtilities::validateSignature($this->signatureData, $gH);
        return TRUE;
    }
    public function getId()
    {
        return $this->id;
    }
    public function setId($Zy)
    {
        $this->id = $Zy;
    }
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }
    public function setIssueInstant($D0)
    {
        $this->issueInstant = $D0;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function setIssuer($Q9)
    {
        $this->issuer = $Q9;
    }
    public function getNameId()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto jh;
        }
        throw new Exception("\101\164\x74\x65\x6d\x70\x74\x65\144\x20\x74\x6f\x20\x72\145\164\x72\151\x65\x76\x65\40\x65\x6e\143\x72\171\160\x74\x65\144\x20\116\141\x6d\145\111\104\x20\167\x69\x74\x68\x6f\165\x74\x20\x64\x65\143\162\171\x70\164\x69\x6e\147\40\151\x74\40\146\x69\162\x73\164\56");
        jh:
        return $this->nameId;
    }
    public function setNameId($VO)
    {
        $this->nameId = $VO;
    }
    public function isNameIdEncrypted()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto Yi;
        }
        return TRUE;
        Yi:
        return FALSE;
    }
    public function encryptNameId(XMLSecurityKey $gH)
    {
        $oi = new DOMDocument();
        $L0 = $oi->createElement("\162\x6f\157\x74");
        $oi->appendChild($L0);
        IDPUtilities::addNameId($L0, $this->nameId);
        $VO = $L0->firstChild;
        IDPUtilities::getContainer()->debugMessage($VO, "\145\156\143\x72\x79\160\x74");
        $kQ = new XMLSecEnc();
        $kQ->setNode($VO);
        $kQ->type = XMLSecEnc::Element;
        $j0 = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
        $j0->generateSessionKey();
        $kQ->encryptKey($gH, $j0);
        $this->encryptedNameId = $kQ->encryptNode($j0);
        $this->nameId = NULL;
    }
    public function decryptNameId(XMLSecurityKey $gH, array $rf = array())
    {
        if (!($this->encryptedNameId === NULL)) {
            goto WI;
        }
        return;
        WI:
        $VO = IDPUtilities::decryptElement($this->encryptedNameId, $gH, $rf);
        IDPUtilities::getContainer()->debugMessage($VO, "\x64\x65\x63\x72\171\160\x74");
        $this->nameId = IDPUtilities::parseNameId($VO);
        $this->encryptedNameId = NULL;
    }
    public function decryptAttributes(XMLSecurityKey $gH, array $rf = array())
    {
        if (!($this->encryptedAttribute === NULL)) {
            goto uK;
        }
        return;
        uK:
        $gU = TRUE;
        $gX = $this->encryptedAttribute;
        foreach ($gX as $d1) {
            $AV = IDPUtilities::decryptElement($d1->getElementsByTagName("\105\156\143\162\171\160\x74\145\144\x44\x61\x74\141")->item(0), $gH, $rf);
            if ($AV->hasAttribute("\116\141\x6d\145")) {
                goto ZH;
            }
            throw new Exception("\x4d\x69\x73\163\x69\x6e\x67\40\x6e\141\155\x65\40\157\x6e\40\74\163\141\155\154\x3a\x41\x74\x74\162\x69\142\165\164\145\x3e\40\x65\154\x65\x6d\145\156\164\x2e");
            ZH:
            $ci = $AV->getAttribute("\116\141\x6d\145");
            if ($AV->hasAttribute("\x4e\x61\x6d\x65\106\157\162\155\x61\164")) {
                goto zH;
            }
            $od = "\x75\x72\156\72\157\141\163\x69\163\x3a\156\x61\155\145\x73\x3a\x74\143\72\x53\101\115\114\72\62\56\60\72\141\x74\x74\162\x6e\x61\x6d\x65\55\x66\x6f\x72\155\x61\x74\72\x75\156\163\160\145\143\x69\146\x69\x65\x64";
            goto MY;
            zH:
            $od = $AV->getAttribute("\x4e\x61\155\145\106\x6f\162\x6d\141\164");
            MY:
            if ($gU) {
                goto eI;
            }
            if (!($this->nameFormat !== $od)) {
                goto r9;
            }
            $this->nameFormat = "\165\162\x6e\72\157\141\163\x69\x73\72\156\x61\x6d\145\163\x3a\164\x63\x3a\123\x41\x4d\114\72\62\56\x30\x3a\x61\164\164\x72\156\141\x6d\x65\55\146\x6f\x72\155\141\x74\x3a\165\x6e\163\x70\x65\x63\x69\x66\x69\145\x64";
            r9:
            goto kv;
            eI:
            $this->nameFormat = $od;
            $gU = FALSE;
            kv:
            if (array_key_exists($ci, $this->attributes)) {
                goto a_;
            }
            $this->attributes[$ci] = array();
            a_:
            $jO = IDPUtilities::xpQuery($AV, "\x2e\x2f\x73\x61\155\154\137\x61\x73\163\145\162\164\151\157\156\x3a\101\164\164\x72\151\x62\165\164\145\126\141\154\165\x65");
            foreach ($jO as $Or) {
                $this->attributes[$ci][] = trim($Or->textContent);
                mr:
            }
            TI:
            KR:
        }
        wt:
    }
    public function getNotBefore()
    {
        return $this->notBefore;
    }
    public function setNotBefore($VF)
    {
        $this->notBefore = $VF;
    }
    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }
    public function setNotOnOrAfter($nJ)
    {
        $this->notOnOrAfter = $nJ;
    }
    public function setEncryptedAttributes($v2)
    {
        $this->requiredEncAttributes = $v2;
    }
    public function getValidAudiences()
    {
        return $this->validAudiences;
    }
    public function setValidAudiences(array $le = NULL)
    {
        $this->validAudiences = $le;
    }
    public function getAuthnInstant()
    {
        return $this->authnInstant;
    }
    public function setAuthnInstant($GL)
    {
        $this->authnInstant = $GL;
    }
    public function getSessionNotOnOrAfter()
    {
        return $this->sessionNotOnOrAfter;
    }
    public function setSessionNotOnOrAfter($Tl)
    {
        $this->sessionNotOnOrAfter = $Tl;
    }
    public function getSessionIndex()
    {
        return $this->sessionIndex;
    }
    public function setSessionIndex($jV)
    {
        $this->sessionIndex = $jV;
    }
    public function getAuthnContext()
    {
        if (empty($this->authnContextClassRef)) {
            goto lb;
        }
        return $this->authnContextClassRef;
        lb:
        if (empty($this->authnContextDeclRef)) {
            goto xl;
        }
        return $this->authnContextDeclRef;
        xl:
        return NULL;
    }
    public function setAuthnContext($jo)
    {
        $this->setAuthnContextClassRef($jo);
    }
    public function getAuthnContextClassRef()
    {
        return $this->authnContextClassRef;
    }
    public function setAuthnContextClassRef($sK)
    {
        $this->authnContextClassRef = $sK;
    }
    public function setAuthnContextDecl(SAML2_XML_Chunk $Of)
    {
        if (empty($this->authnContextDeclRef)) {
            goto WA;
        }
        throw new Exception("\101\165\164\x68\156\x43\x6f\x6e\164\x65\x78\x74\104\145\x63\154\x52\x65\146\x20\151\x73\x20\141\x6c\x72\145\x61\x64\x79\x20\x72\x65\x67\151\x73\164\145\162\145\144\41\x20\115\x61\x79\40\x6f\156\154\171\40\150\x61\166\x65\x20\145\151\164\x68\145\x72\x20\x61\40\x44\145\143\154\40\x6f\162\40\x61\40\104\145\x63\x6c\x52\145\x66\54\40\156\157\164\40\x62\157\x74\x68\x21");
        WA:
        $this->authnContextDecl = $Of;
    }
    public function getAuthnContextDecl()
    {
        return $this->authnContextDecl;
    }
    public function setAuthnContextDeclRef($ak)
    {
        if (empty($this->authnContextDecl)) {
            goto b3;
        }
        throw new Exception("\101\x75\x74\x68\x6e\x43\x6f\x6e\164\145\170\164\x44\145\x63\154\x20\151\x73\x20\141\x6c\x72\x65\x61\144\x79\40\x72\145\147\x69\163\x74\x65\x72\x65\144\41\x20\115\x61\171\40\x6f\x6e\x6c\x79\40\150\141\x76\x65\x20\x65\x69\164\150\145\x72\40\x61\x20\104\145\143\x6c\x20\157\x72\x20\141\40\104\x65\143\x6c\x52\145\x66\x2c\x20\x6e\x6f\164\40\x62\157\x74\x68\x21");
        b3:
        $this->authnContextDeclRef = $ak;
    }
    public function getAuthnContextDeclRef()
    {
        return $this->authnContextDeclRef;
    }
    public function getAuthenticatingAuthority()
    {
        return $this->AuthenticatingAuthority;
    }
    public function setAuthenticatingAuthority($R9)
    {
        $this->AuthenticatingAuthority = $R9;
    }
    public function getAttributes()
    {
        return $this->attributes;
    }
    public function setAttributes(array $gX)
    {
        $this->attributes = $gX;
    }
    public function getAttributeNameFormat()
    {
        return $this->nameFormat;
    }
    public function setAttributeNameFormat($od)
    {
        $this->nameFormat = $od;
    }
    public function getSubjectConfirmation()
    {
        return $this->SubjectConfirmation;
    }
    public function setSubjectConfirmation(array $G8)
    {
        $this->SubjectConfirmation = $G8;
    }
    public function getSignatureKey()
    {
        return $this->signatureKey;
    }
    public function setSignatureKey(XMLsecurityKey $WK = NULL)
    {
        $this->signatureKey = $WK;
    }
    public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }
    public function setEncryptionKey(XMLSecurityKey $BW = NULL)
    {
        $this->encryptionKey = $BW;
    }
    public function setCertificates(array $iW)
    {
        $this->certificates = $iW;
    }
    public function getCertificates()
    {
        return $this->certificates;
    }
    public function getWasSignedAtConstruction()
    {
        return $this->wasSignedAtConstruction;
    }
    public function toXML(DOMNode $GO = NULL)
    {
        if ($GO === NULL) {
            goto Ou;
        }
        $s6 = $GO->ownerDocument;
        goto I5;
        Ou:
        $s6 = new DOMDocument();
        $GO = $s6;
        I5:
        $L0 = $s6->createElementNS("\165\x72\x6e\72\x6f\141\x73\151\163\72\156\x61\155\x65\x73\x3a\x74\143\72\123\101\x4d\114\x3a\62\x2e\x30\72\x61\163\163\x65\162\164\151\157\156", "\163\x61\155\x6c\72" . "\101\x73\163\x65\x72\164\x69\x6f\x6e");
        $GO->appendChild($L0);
        $L0->setAttributeNS("\x75\x72\x6e\x3a\157\x61\x73\151\163\x3a\x6e\x61\x6d\x65\163\x3a\x74\x63\x3a\123\101\x4d\x4c\72\x32\56\60\x3a\160\x72\x6f\164\x6f\x63\x6f\154", "\163\x61\x6d\x6c\160\x3a\x74\x6d\x70", "\164\x6d\x70");
        $L0->removeAttributeNS("\x75\162\156\x3a\x6f\x61\163\151\x73\72\x6e\141\x6d\x65\x73\72\164\143\x3a\x53\101\x4d\114\x3a\62\x2e\60\72\x70\x72\x6f\164\157\x63\x6f\154", "\164\155\x70");
        $L0->setAttributeNS("\x68\164\x74\160\72\x2f\x2f\x77\167\x77\56\167\63\x2e\x6f\x72\x67\x2f\x32\x30\x30\x31\57\x58\x4d\x4c\x53\x63\x68\x65\155\141\x2d\151\156\163\x74\x61\156\x63\x65", "\x78\x73\151\x3a\164\x6d\x70", "\x74\155\x70");
        $L0->removeAttributeNS("\x68\164\164\160\72\57\x2f\x77\x77\x77\x2e\x77\x33\x2e\157\x72\x67\57\x32\x30\x30\x31\57\130\115\114\123\143\x68\145\x6d\x61\x2d\x69\x6e\x73\164\x61\x6e\143\x65", "\164\155\x70");
        $L0->setAttributeNS("\150\164\164\x70\x3a\x2f\57\x77\167\167\x2e\167\x33\x2e\x6f\162\147\x2f\62\x30\60\61\x2f\130\x4d\x4c\123\x63\x68\145\x6d\141", "\x78\163\72\164\155\160", "\x74\x6d\x70");
        $L0->removeAttributeNS("\150\164\164\160\72\57\x2f\x77\167\x77\56\x77\x33\x2e\157\x72\x67\57\62\60\x30\61\57\x58\x4d\x4c\123\143\x68\145\x6d\141", "\x74\155\160");
        $L0->setAttribute("\x49\104", $this->id);
        $L0->setAttribute("\126\145\x72\x73\x69\157\156", "\62\56\60");
        $L0->setAttribute("\111\163\163\x75\x65\111\x6e\163\164\141\x6e\164", gmdate("\x59\x2d\155\x2d\x64\x5c\124\x48\72\x69\x3a\163\x5c\132", $this->issueInstant));
        $Q9 = IDPUtilities::addString($L0, "\x75\x72\x6e\x3a\157\x61\163\151\x73\x3a\x6e\x61\x6d\x65\x73\x3a\x74\x63\72\123\x41\x4d\114\x3a\62\x2e\60\72\x61\x73\163\145\x72\164\x69\x6f\156", "\x73\141\x6d\x6c\72\x49\x73\x73\x75\145\x72", $this->issuer);
        $this->addSubject($L0);
        $this->addConditions($L0);
        $this->addAuthnStatement($L0);
        if ($this->requiredEncAttributes == FALSE) {
            goto F0;
        }
        $this->addEncryptedAttributeStatement($L0);
        goto dt;
        F0:
        $this->addAttributeStatement($L0);
        dt:
        if (!($this->signatureKey !== NULL)) {
            goto GO;
        }
        IDPUtilities::insertSignature($this->signatureKey, $this->certificates, $L0, $Q9->nextSibling);
        GO:
        return $L0;
    }
    private function addSubject(DOMElement $L0)
    {
        if (!($this->nameId === NULL && $this->encryptedNameId === NULL)) {
            goto JV;
        }
        return;
        JV:
        $lY = $L0->ownerDocument->createElementNS("\x75\x72\156\72\157\x61\163\x69\x73\72\x6e\x61\x6d\145\163\72\164\143\x3a\123\101\115\114\x3a\62\x2e\x30\x3a\141\163\163\145\x72\164\x69\157\x6e", "\x73\x61\155\x6c\72\123\165\x62\x6a\x65\x63\164");
        $L0->appendChild($lY);
        if ($this->encryptedNameId === NULL) {
            goto bT;
        }
        $t2 = $lY->ownerDocument->createElementNS("\165\x72\x6e\x3a\157\x61\163\x69\163\72\x6e\141\155\145\163\x3a\164\143\x3a\123\101\x4d\114\72\62\x2e\x30\x3a\141\163\163\x65\162\x74\x69\x6f\x6e", "\x73\x61\x6d\154\x3a" . "\105\x6e\143\162\171\x70\164\x65\144\111\104");
        $lY->appendChild($t2);
        $t2->appendChild($lY->ownerDocument->importNode($this->encryptedNameId, TRUE));
        goto BE;
        bT:
        IDPUtilities::addNameId($lY, $this->nameId);
        BE:
        foreach ($this->SubjectConfirmation as $CW) {
            $CW->toXML($lY);
            EN:
        }
        j4:
    }
    private function addConditions(DOMElement $L0)
    {
        $s6 = $L0->ownerDocument;
        $ow = $s6->createElementNS("\165\x72\156\x3a\x6f\141\x73\x69\x73\x3a\x6e\x61\155\x65\x73\72\x74\143\x3a\x53\101\115\114\x3a\x32\56\60\x3a\x61\x73\163\145\162\164\x69\157\156", "\x73\x61\x6d\154\72\103\157\x6e\x64\151\164\x69\x6f\156\163");
        $L0->appendChild($ow);
        if (!($this->notBefore !== NULL)) {
            goto me;
        }
        $ow->setAttribute("\x4e\157\x74\x42\x65\x66\x6f\x72\x65", gmdate("\131\55\x6d\x2d\144\x5c\124\110\x3a\151\72\163\134\132", $this->notBefore));
        me:
        if (!($this->notOnOrAfter !== NULL)) {
            goto dh;
        }
        $ow->setAttribute("\116\x6f\x74\117\x6e\117\x72\x41\146\164\x65\x72", gmdate("\x59\55\x6d\55\x64\134\124\110\72\x69\x3a\163\134\132", $this->notOnOrAfter));
        dh:
        if (!($this->validAudiences !== NULL)) {
            goto ln;
        }
        $Z4 = $s6->createElementNS("\x75\x72\x6e\72\x6f\x61\x73\151\163\x3a\156\141\x6d\x65\163\72\164\143\x3a\123\x41\x4d\x4c\x3a\x32\56\x30\x3a\x61\x73\x73\x65\162\x74\x69\x6f\156", "\x73\141\155\154\72\101\x75\x64\x69\x65\156\143\145\122\x65\163\x74\x72\x69\x63\164\x69\x6f\x6e");
        $ow->appendChild($Z4);
        IDPUtilities::addStrings($Z4, "\x75\162\x6e\72\x6f\x61\x73\151\x73\x3a\156\141\x6d\x65\x73\x3a\164\143\x3a\123\101\x4d\114\72\62\56\60\72\x61\163\x73\x65\x72\x74\151\157\156", "\163\141\155\x6c\x3a\101\x75\144\151\145\156\143\145", FALSE, $this->validAudiences);
        ln:
    }
    private function addAuthnStatement(DOMElement $L0)
    {
        if (!($this->authnInstant === NULL || $this->authnContextClassRef === NULL && $this->authnContextDecl === NULL && $this->authnContextDeclRef === NULL)) {
            goto t6;
        }
        return;
        t6:
        $s6 = $L0->ownerDocument;
        $NI = $s6->createElementNS("\165\x72\156\x3a\x6f\141\x73\151\163\x3a\x6e\141\155\x65\163\x3a\x74\x63\72\x53\x41\x4d\x4c\x3a\x32\56\x30\72\141\x73\163\x65\x72\x74\x69\x6f\156", "\163\x61\155\x6c\72\x41\165\164\150\156\x53\164\x61\164\145\155\x65\x6e\x74");
        $L0->appendChild($NI);
        $NI->setAttribute("\x41\165\x74\x68\x6e\x49\156\x73\164\x61\x6e\164", gmdate("\x59\55\x6d\55\144\x5c\x54\110\72\151\72\x73\134\132", $this->authnInstant));
        if (!($this->sessionNotOnOrAfter !== NULL)) {
            goto be;
        }
        $NI->setAttribute("\123\x65\163\163\151\157\x6e\x4e\157\x74\x4f\156\117\x72\x41\x66\164\x65\x72", gmdate("\x59\55\x6d\55\x64\134\x54\x48\72\x69\x3a\163\134\132", $this->sessionNotOnOrAfter));
        be:
        if (!($this->sessionIndex !== NULL)) {
            goto bU;
        }
        $NI->setAttribute("\x53\x65\163\163\x69\x6f\x6e\111\x6e\x64\145\170", $this->sessionIndex);
        bU:
        $J5 = $s6->createElementNS("\x75\x72\156\x3a\157\141\163\151\163\72\156\x61\x6d\145\163\x3a\164\x63\72\x53\x41\x4d\114\x3a\62\x2e\x30\72\141\x73\163\x65\162\x74\151\157\x6e", "\163\x61\155\154\x3a\x41\165\x74\150\156\x43\x6f\x6e\164\145\170\x74");
        $NI->appendChild($J5);
        if (empty($this->authnContextClassRef)) {
            goto Xv;
        }
        IDPUtilities::addString($J5, "\x75\162\x6e\72\x6f\141\x73\x69\163\x3a\156\141\155\145\163\72\x74\143\x3a\123\x41\115\114\72\x32\x2e\60\x3a\x61\x73\163\145\x72\164\151\x6f\156", "\163\141\155\x6c\x3a\x41\x75\x74\150\x6e\x43\157\x6e\x74\x65\x78\x74\x43\x6c\x61\163\163\x52\x65\x66", $this->authnContextClassRef);
        Xv:
        if (empty($this->authnContextDecl)) {
            goto w_;
        }
        $this->authnContextDecl->toXML($J5);
        w_:
        if (empty($this->authnContextDeclRef)) {
            goto X1;
        }
        IDPUtilities::addString($J5, "\165\x72\156\x3a\157\x61\x73\151\x73\72\156\141\x6d\x65\163\x3a\164\143\x3a\x53\101\115\114\x3a\62\56\60\x3a\141\x73\163\145\162\164\x69\x6f\156", "\x73\x61\155\154\72\x41\x75\x74\x68\x6e\103\x6f\x6e\x74\x65\x78\x74\104\x65\x63\154\x52\145\x66", $this->authnContextDeclRef);
        X1:
        IDPUtilities::addStrings($J5, "\165\x72\156\x3a\157\141\163\151\x73\72\x6e\141\155\x65\x73\72\x74\x63\x3a\123\x41\115\x4c\x3a\x32\x2e\60\72\x61\x73\163\145\162\x74\151\157\156", "\163\x61\x6d\x6c\x3a\x41\165\x74\x68\x65\156\x74\x69\x63\x61\x74\151\156\x67\x41\165\164\x68\157\x72\x69\164\171", FALSE, $this->AuthenticatingAuthority);
    }
    private function addAttributeStatement(DOMElement $L0)
    {
        if (!empty($this->attributes)) {
            goto AE;
        }
        return;
        AE:
        $s6 = $L0->ownerDocument;
        $MS = $s6->createElementNS("\165\x72\156\x3a\x6f\141\163\x69\163\72\x6e\x61\x6d\x65\163\x3a\164\x63\x3a\123\x41\x4d\x4c\x3a\x32\56\60\72\x61\x73\x73\145\x72\x74\151\157\156", "\163\141\155\x6c\x3a\101\164\x74\162\x69\x62\165\164\145\x53\x74\x61\x74\x65\155\145\x6e\164");
        $L0->appendChild($MS);
        foreach ($this->attributes as $ci => $jO) {
            $AV = $s6->createElementNS("\x75\162\156\72\157\x61\163\151\163\x3a\156\141\x6d\x65\163\72\164\143\x3a\x53\101\x4d\114\x3a\x32\56\x30\x3a\141\163\x73\145\162\164\151\157\156", "\x73\141\155\154\72\x41\x74\164\162\x69\142\165\x74\x65");
            $MS->appendChild($AV);
            $AV->setAttribute("\x4e\141\155\x65", $ci);
            if (!($this->nameFormat !== "\165\162\x6e\72\157\x61\163\x69\163\72\156\x61\x6d\145\163\72\164\x63\x3a\x53\x41\x4d\x4c\72\62\x2e\x30\72\x61\x74\164\x72\x6e\141\x6d\145\55\146\157\162\155\141\x74\72\x75\156\x73\160\x65\x63\151\146\151\x65\144")) {
                goto G4;
            }
            $AV->setAttribute("\116\141\x6d\145\x46\x6f\x72\x6d\141\x74", $this->nameFormat);
            G4:
            foreach ($jO as $Or) {
                if (is_string($Or)) {
                    goto QU;
                }
                if (is_int($Or)) {
                    goto fP;
                }
                $i9 = NULL;
                goto Mp;
                QU:
                $i9 = "\x78\163\x3a\x73\164\x72\151\x6e\147";
                goto Mp;
                fP:
                $i9 = "\170\x73\x3a\x69\x6e\x74\x65\x67\145\x72";
                Mp:
                $xN = $s6->createElementNS("\x75\x72\156\72\157\141\x73\151\163\x3a\156\141\155\x65\x73\x3a\164\x63\x3a\123\101\115\x4c\72\62\x2e\x30\x3a\141\x73\163\145\162\x74\x69\157\156", "\163\141\155\x6c\x3a\101\164\x74\x72\151\x62\165\x74\145\126\141\154\x75\x65");
                $AV->appendChild($xN);
                if (!($i9 !== NULL)) {
                    goto Xk;
                }
                $xN->setAttributeNS("\150\x74\164\160\72\57\x2f\167\167\x77\56\x77\x33\56\x6f\162\147\x2f\62\x30\x30\61\57\130\x4d\114\123\x63\150\x65\x6d\x61\55\151\156\163\164\141\156\143\x65", "\x78\x73\151\x3a\x74\x79\160\145", $i9);
                Xk:
                if (!is_null($Or)) {
                    goto W4;
                }
                $xN->setAttributeNS("\x68\x74\164\160\x3a\57\57\167\167\x77\56\167\x33\x2e\x6f\x72\x67\57\x32\x30\60\x31\x2f\x58\115\x4c\123\143\x68\145\155\x61\55\x69\156\163\164\x61\x6e\x63\145", "\170\x73\151\x3a\156\x69\x6c", "\x74\162\x75\145");
                W4:
                if ($Or instanceof DOMNodeList) {
                    goto au;
                }
                $xN->appendChild($s6->createTextNode($Or));
                goto uE;
                au:
                $c0 = 0;
                He:
                if (!($c0 < $Or->length)) {
                    goto hl;
                }
                $li = $s6->importNode($Or->item($c0), TRUE);
                $xN->appendChild($li);
                xv:
                $c0++;
                goto He;
                hl:
                uE:
                bk:
            }
            uJ:
            GV:
        }
        xk:
    }
    private function addEncryptedAttributeStatement(DOMElement $L0)
    {
        if (!($this->requiredEncAttributes == FALSE)) {
            goto pG;
        }
        return;
        pG:
        $s6 = $L0->ownerDocument;
        $MS = $s6->createElementNS("\x75\162\156\x3a\x6f\x61\163\151\x73\x3a\x6e\x61\x6d\x65\x73\72\x74\x63\72\x53\101\x4d\114\72\x32\x2e\x30\72\141\x73\163\145\x72\164\x69\x6f\x6e", "\x73\x61\x6d\154\x3a\101\164\x74\162\151\x62\165\x74\x65\123\x74\x61\x74\x65\155\x65\x6e\x74");
        $L0->appendChild($MS);
        foreach ($this->attributes as $ci => $jO) {
            $Md = new DOMDocument();
            $AV = $Md->createElementNS("\165\162\156\72\x6f\141\x73\x69\x73\x3a\156\141\x6d\x65\163\x3a\164\x63\x3a\x53\101\x4d\114\72\x32\x2e\60\x3a\x61\163\x73\x65\162\x74\x69\157\x6e", "\x73\x61\x6d\154\72\x41\x74\x74\162\x69\142\165\164\145");
            $AV->setAttribute("\x4e\x61\155\x65", $ci);
            $Md->appendChild($AV);
            if (!($this->nameFormat !== "\x75\162\x6e\72\x6f\141\163\x69\163\x3a\156\x61\155\145\163\x3a\x74\x63\72\123\101\115\x4c\x3a\62\x2e\60\x3a\x61\x74\164\162\x6e\141\x6d\145\55\146\157\x72\x6d\x61\x74\x3a\165\x6e\163\160\145\143\151\x66\151\145\144")) {
                goto y7;
            }
            $AV->setAttribute("\116\141\x6d\145\106\x6f\162\x6d\141\164", $this->nameFormat);
            y7:
            foreach ($jO as $Or) {
                if (is_string($Or)) {
                    goto kU;
                }
                if (is_int($Or)) {
                    goto Gw;
                }
                $i9 = NULL;
                goto JP;
                kU:
                $i9 = "\x78\x73\72\163\164\x72\x69\x6e\x67";
                goto JP;
                Gw:
                $i9 = "\x78\x73\x3a\x69\156\x74\145\x67\145\162";
                JP:
                $xN = $Md->createElementNS("\165\162\x6e\72\x6f\141\x73\x69\x73\72\x6e\141\155\x65\x73\x3a\x74\x63\72\x53\x41\115\x4c\x3a\62\56\60\x3a\141\x73\x73\145\162\164\151\x6f\x6e", "\163\141\x6d\x6c\72\x41\x74\x74\x72\x69\142\165\x74\x65\x56\141\x6c\x75\x65");
                $AV->appendChild($xN);
                if (!($i9 !== NULL)) {
                    goto Zp;
                }
                $xN->setAttributeNS("\x68\x74\164\160\x3a\x2f\57\x77\x77\167\56\167\63\x2e\x6f\x72\x67\57\x32\x30\60\61\x2f\x58\115\x4c\x53\143\150\x65\155\141\x2d\151\156\x73\164\141\156\143\145", "\170\x73\x69\x3a\x74\171\x70\x65", $i9);
                Zp:
                if ($Or instanceof DOMNodeList) {
                    goto dD;
                }
                $xN->appendChild($Md->createTextNode($Or));
                goto yA;
                dD:
                $c0 = 0;
                lQ:
                if (!($c0 < $Or->length)) {
                    goto tJ;
                }
                $li = $Md->importNode($Or->item($c0), TRUE);
                $xN->appendChild($li);
                rj:
                $c0++;
                goto lQ;
                tJ:
                yA:
                Qz:
            }
            NW:
            $UE = new XMLSecEnc();
            $UE->setNode($Md->documentElement);
            $UE->type = "\150\164\164\x70\x3a\x2f\57\x77\x77\x77\56\x77\63\x2e\157\162\147\x2f\62\x30\x30\61\57\x30\x34\x2f\170\x6d\154\x65\156\x63\x23\x45\154\145\x6d\x65\156\x74";
            $j0 = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
            $j0->generateSessionKey();
            $UE->encryptKey($this->encryptionKey, $j0);
            $Mw = $UE->encryptNode($j0);
            $hN = $s6->createElementNS("\x75\162\156\72\157\x61\163\x69\x73\x3a\156\x61\155\x65\163\72\x74\143\x3a\123\101\x4d\114\x3a\x32\56\x30\x3a\141\x73\163\x65\162\164\151\x6f\156", "\x73\141\155\x6c\72\105\x6e\143\162\171\160\x74\145\x64\x41\x74\164\x72\x69\142\x75\x74\x65");
            $MS->appendChild($hN);
            $YH = $s6->importNode($Mw, TRUE);
            $hN->appendChild($YH);
            Fx:
        }
        D_:
    }
}
