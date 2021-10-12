<?php


include_once "\x49\104\120\x55\164\x69\154\x69\164\x69\x65\163\x2e\160\150\x70";
class SAML2_LogoutRequest
{
    private $tagName;
    private $id;
    private $issuer;
    private $destination;
    private $issueInstant;
    private $certificates;
    private $validators;
    private $notOnOrAfter;
    private $encryptedNameId;
    private $nameId;
    private $sessionIndexes;
    public function __construct(DOMElement $hB = NULL)
    {
        $this->tagName = "\x4c\157\147\157\x75\x74\x52\145\161\165\x65\163\164";
        $this->id = IDPUtilities::generateID();
        $this->issueInstant = time();
        $this->certificates = array();
        $this->validators = array();
        if (!($hB === NULL)) {
            goto j7;
        }
        return;
        j7:
        if ($hB->hasAttribute("\x49\104")) {
            goto Hf;
        }
        throw new Exception("\x4d\151\163\x73\x69\x6e\x67\40\111\x44\x20\x61\x74\x74\162\151\x62\x75\164\145\40\x6f\x6e\x20\x53\101\115\x4c\40\155\x65\x73\x73\x61\x67\x65\x2e");
        Hf:
        $this->id = $hB->getAttribute("\111\x44");
        if (!($hB->getAttribute("\x56\x65\162\x73\151\157\156") !== "\62\56\x30")) {
            goto A8;
        }
        throw new Exception("\125\x6e\x73\165\x70\160\157\162\164\x65\x64\x20\166\x65\x72\x73\151\157\x6e\x3a\x20" . $hB->getAttribute("\126\145\162\x73\151\x6f\x6e"));
        A8:
        $this->issueInstant = IDPUtilities::xsDateTimeToTimestamp($hB->getAttribute("\x49\163\x73\x75\x65\x49\x6e\163\x74\x61\x6e\x74"));
        if (!$hB->hasAttribute("\104\145\163\x74\x69\156\141\164\151\157\x6e")) {
            goto dQ;
        }
        $this->destination = $hB->getAttribute("\x44\145\163\x74\x69\x6e\x61\164\x69\x6f\x6e");
        dQ:
        $Q9 = IDPUtilities::xpQuery($hB, "\56\x2f\163\141\x6d\154\x5f\141\163\x73\145\162\164\151\157\156\x3a\x49\163\163\165\145\x72");
        if (empty($Q9)) {
            goto N3;
        }
        $this->issuer = trim($Q9[0]->textContent);
        N3:
        try {
            $Xd = IDPUtilities::validateElement($hB);
            if (!($Xd !== FALSE)) {
                goto Tl;
            }
            $this->certificates = $Xd["\x43\145\x72\164\151\x66\x69\x63\141\x74\x65\x73"];
            $this->validators[] = array("\106\165\156\x63\x74\x69\x6f\156" => array("\111\x44\x50\x55\164\151\x6c\x69\x74\x69\145\163", "\166\x61\x6c\151\x64\141\164\x65\123\x69\x67\x6e\141\164\165\162\x65"), "\104\141\164\141" => $Xd);
            Tl:
        } catch (Exception $w4) {
        }
        $this->sessionIndexes = array();
        if (!$hB->hasAttribute("\x4e\x6f\x74\x4f\156\117\162\101\146\x74\x65\162")) {
            goto aE;
        }
        $this->notOnOrAfter = IDPUtilities::xsDateTimeToTimestamp($hB->getAttribute("\116\157\164\x4f\156\x4f\162\101\146\x74\x65\162"));
        aE:
        $VO = IDPUtilities::xpQuery($hB, "\56\57\163\x61\x6d\x6c\137\x61\163\x73\145\162\x74\x69\x6f\156\72\116\x61\x6d\x65\111\x44\x20\174\x20\x2e\57\163\141\x6d\154\137\141\x73\163\x65\162\x74\151\157\x6e\72\105\156\x63\162\x79\160\x74\145\x64\111\104\x2f\x78\x65\156\x63\x3a\x45\x6e\x63\x72\x79\160\164\x65\x64\104\x61\164\x61");
        if (empty($VO)) {
            goto KF;
        }
        if (count($VO) > 1) {
            goto QK;
        }
        goto Sy;
        KF:
        throw new Exception("\115\151\163\x73\151\x6e\147\40\74\x73\x61\155\154\72\116\x61\x6d\x65\111\x44\x3e\40\157\x72\40\74\x73\x61\x6d\154\x3a\105\156\x63\162\171\x70\164\145\x64\111\x44\x3e\x20\x69\x6e\40\x3c\163\x61\x6d\x6c\x70\x3a\114\157\x67\157\165\164\122\x65\x71\165\x65\x73\164\76\56");
        goto Sy;
        QK:
        throw new Exception("\115\157\162\x65\40\164\x68\141\156\40\157\156\145\x20\x3c\x73\x61\x6d\x6c\x3a\x4e\x61\x6d\145\111\x44\76\x20\157\162\40\74\163\x61\x6d\154\72\105\x6e\x63\x72\171\x70\x74\145\x64\104\76\x20\x69\x6e\40\x3c\x73\x61\155\154\x70\72\x4c\x6f\147\157\165\x74\122\145\161\x75\x65\163\164\76\x2e");
        Sy:
        $VO = $VO[0];
        if ($VO->localName === "\x45\156\x63\162\171\160\164\x65\x64\104\141\x74\x61") {
            goto xA;
        }
        $this->nameId = IDPUtilities::parseNameId($VO);
        goto Wa;
        xA:
        $this->encryptedNameId = $VO;
        Wa:
        $Wc = IDPUtilities::xpQuery($hB, "\x2e\57\163\141\155\154\137\x70\162\x6f\164\x6f\143\157\154\x3a\x53\145\163\x73\x69\x6f\156\111\x6e\x64\145\x78");
        foreach ($Wc as $jV) {
            $this->sessionIndexes[] = trim($jV->textContent);
            dq:
        }
        UZ:
    }
    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }
    public function setNotOnOrAfter($nJ)
    {
        $this->notOnOrAfter = $nJ;
    }
    public function isNameIdEncrypted()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto GD;
        }
        return TRUE;
        GD:
        return FALSE;
    }
    public function encryptNameId(XMLSecurityKey $gH)
    {
        $oi = new DOMDocument();
        $L0 = $oi->createElement("\x72\157\x6f\164");
        $oi->appendChild($L0);
        SAML2_Utils::addNameId($L0, $this->nameId);
        $VO = $L0->firstChild;
        SAML2_Utils::getContainer()->debugMessage($VO, "\145\156\143\162\171\160\x74");
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
            goto uZ;
        }
        return;
        uZ:
        $VO = SAML2_Utils::decryptElement($this->encryptedNameId, $gH, $rf);
        SAML2_Utils::getContainer()->debugMessage($VO, "\144\x65\x63\x72\x79\x70\164");
        $this->nameId = SAML2_Utils::parseNameId($VO);
        $this->encryptedNameId = NULL;
    }
    public function getNameId()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto JH;
        }
        throw new Exception("\101\x74\164\x65\x6d\x70\164\145\144\40\x74\x6f\40\162\145\164\x72\x69\x65\166\x65\x20\x65\156\x63\162\171\160\164\x65\144\40\116\141\155\145\111\104\40\167\x69\164\150\x6f\165\164\40\144\145\143\x72\171\x70\164\151\x6e\147\40\151\164\x20\x66\151\x72\163\x74\x2e");
        JH:
        return $this->nameId;
    }
    public function setNameId($VO)
    {
        $this->nameId = $VO;
    }
    public function getSessionIndexes()
    {
        return $this->sessionIndexes;
    }
    public function setSessionIndexes(array $Wc)
    {
        $this->sessionIndexes = $Wc;
    }
    public function getSessionIndex()
    {
        if (!empty($this->sessionIndexes)) {
            goto SF;
        }
        return NULL;
        SF:
        return $this->sessionIndexes[0];
    }
    public function setSessionIndex($jV)
    {
        if (is_null($jV)) {
            goto nK;
        }
        $this->sessionIndexes = array($jV);
        goto Ds;
        nK:
        $this->sessionIndexes = array();
        Ds:
    }
    public function toUnsignedXML()
    {
        $L0 = parent::toUnsignedXML();
        if (!($this->notOnOrAfter !== NULL)) {
            goto cR;
        }
        $L0->setAttribute("\116\157\164\117\156\117\x72\x41\x66\x74\145\x72", gmdate("\x59\55\x6d\55\144\134\x54\110\x3a\x69\72\163\134\132", $this->notOnOrAfter));
        cR:
        if ($this->encryptedNameId === NULL) {
            goto zF;
        }
        $t2 = $L0->ownerDocument->createElementNS(SAML2_Const::NS_SAML, "\x73\x61\x6d\154\72" . "\105\x6e\143\162\x79\x70\x74\145\x64\x49\x44");
        $L0->appendChild($t2);
        $t2->appendChild($L0->ownerDocument->importNode($this->encryptedNameId, TRUE));
        goto L3;
        zF:
        SAML2_Utils::addNameId($L0, $this->nameId);
        L3:
        foreach ($this->sessionIndexes as $jV) {
            SAML2_Utils::addString($L0, SAML2_Const::NS_SAMLP, "\x53\145\163\x73\x69\157\156\x49\156\144\145\x78", $jV);
            qg:
        }
        dd:
        return $L0;
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
    public function getDestination()
    {
        return $this->destination;
    }
    public function setDestination($HF)
    {
        $this->destination = $HF;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function setIssuer($Q9)
    {
        $this->issuer = $Q9;
    }
}
