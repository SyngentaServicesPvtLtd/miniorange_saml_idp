<?php


class AuthnRequest
{
    private $nameIdPolicy;
    private $forceAuthn;
    private $isPassive;
    private $RequesterID = array();
    private $assertionConsumerServiceURL;
    private $protocolBinding;
    private $requestedAuthnContext;
    private $namespaceURI;
    private $destination;
    private $issuer;
    private $version;
    private $issueInstant;
    private $requestID;
    public function __construct(DOMElement $hB = null)
    {
        $this->nameIdPolicy = array();
        $this->forceAuthn = false;
        $this->isPassive = false;
        if (!($hB === null)) {
            goto qQ;
        }
        return;
        qQ:
        $this->forceAuthn = IDPUtilities::parseBoolean($hB, "\106\157\x72\143\145\x41\x75\164\x68\x6e", false);
        $this->isPassive = IDPUtilities::parseBoolean($hB, "\x49\x73\x50\141\x73\163\x69\166\x65", false);
        if (!$hB->hasAttribute("\x41\163\x73\x65\x72\x74\x69\157\156\103\157\156\x73\x75\155\145\162\123\145\162\166\x69\143\x65\x55\122\114")) {
            goto jS;
        }
        $this->assertionConsumerServiceURL = $hB->getAttribute("\x41\163\163\145\x72\x74\151\x6f\x6e\103\x6f\156\x73\165\x6d\x65\x72\123\x65\x72\166\x69\143\145\x55\x52\114");
        jS:
        if (!$hB->hasAttribute("\x50\x72\157\x74\x6f\143\x6f\x6c\102\151\x6e\x64\x69\x6e\x67")) {
            goto EF;
        }
        $this->protocolBinding = $hB->getAttribute("\x50\x72\x6f\x74\157\143\157\x6c\102\x69\156\144\x69\156\147");
        EF:
        if (!$hB->hasAttribute("\101\164\x74\x72\x69\142\x75\x74\145\103\157\156\163\165\155\151\156\147\123\x65\162\166\151\x63\x65\111\x6e\x64\145\170")) {
            goto Cp;
        }
        $this->attributeConsumingServiceIndex = (int) $hB->getAttribute("\101\164\164\x72\151\142\165\164\145\103\x6f\156\163\x75\x6d\x69\x6e\x67\x53\145\x72\166\x69\x63\145\x49\x6e\x64\145\170");
        Cp:
        if (!$hB->hasAttribute("\x41\163\x73\x65\162\x74\151\x6f\x6e\103\157\x6e\x73\x75\155\145\x72\x53\x65\x72\x76\151\143\145\111\x6e\144\x65\170")) {
            goto vw;
        }
        $this->assertionConsumerServiceIndex = (int) $hB->getAttribute("\101\163\163\145\x72\x74\x69\x6f\x6e\103\x6f\156\x73\165\155\x65\x72\123\x65\x72\166\151\x63\x65\111\x6e\x64\145\170");
        vw:
        if (!$hB->hasAttribute("\x44\x65\x73\164\x69\x6e\141\x74\151\x6f\156")) {
            goto Ya;
        }
        $this->destination = $hB->getAttribute("\104\145\x73\164\x69\156\141\x74\151\x6f\156");
        Ya:
        if (!isset($hB->namespaceURI)) {
            goto RX;
        }
        $this->namespaceURI = $hB->namespaceURI;
        RX:
        if (!$hB->hasAttribute("\126\145\x72\163\x69\157\x6e")) {
            goto b6;
        }
        $this->version = $hB->getAttribute("\x56\145\x72\163\x69\x6f\156");
        b6:
        if (!$hB->hasAttribute("\x49\x73\x73\x75\x65\x49\156\x73\x74\141\156\164")) {
            goto rN;
        }
        $this->issueInstant = $hB->getAttribute("\111\163\163\x75\x65\x49\x6e\163\164\x61\x6e\x74");
        rN:
        if (!$hB->hasAttribute("\x49\x44")) {
            goto wL;
        }
        $this->requestID = $hB->getAttribute("\x49\104");
        wL:
        $this->parseNameIdPolicy($hB);
        $this->parseIssuer($hB);
        $this->parseRequestedAuthnContext($hB);
        $this->parseScoping($hB);
    }
    public function getNameIdPolicy()
    {
        return $this->nameIdPolicy;
    }
    public function getForceAuthn()
    {
        return $this->forceAuthn;
    }
    public function getVersion()
    {
        return $this->version;
    }
    public function getRequestID()
    {
        return $this->requestID;
    }
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }
    public function getDestination()
    {
        return $this->destination;
    }
    public function getIsPassive()
    {
        return $this->isPassive;
    }
    public function getIDPList()
    {
        return $this->IDPList;
    }
    public function getProxyCount()
    {
        return $this->ProxyCount;
    }
    public function getRequesterID()
    {
        return $this->RequesterID;
    }
    public function getNamespaceURI()
    {
        return $this->namespaceURI;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function getAssertionConsumerServiceURL()
    {
        return $this->assertionConsumerServiceURL;
    }
    public function getProtocolBinding()
    {
        return $this->protocolBinding;
    }
    public function getAttributeConsumingServiceIndex()
    {
        return $this->attributeConsumingServiceIndex;
    }
    public function getAssertionConsumerServiceIndex()
    {
        return $this->assertionConsumerServiceIndex;
    }
    public function getRequestedAuthnContext()
    {
        return $this->requestedAuthnContext;
    }
    protected function parseIssuer(DOMElement $hB)
    {
        $Q9 = IDPUtilities::xpQuery($hB, "\56\57\x73\141\155\154\x5f\141\163\x73\145\162\164\x69\x6f\x6e\72\111\x73\x73\165\145\162");
        if (!empty($Q9)) {
            goto Pp;
        }
        throw new Exception("\x4d\151\163\x73\151\x6e\147\x20\x3c\163\141\x6d\154\x3a\x49\x73\x73\165\x65\x72\76\40\151\156\x20\141\163\x73\x65\162\x74\x69\157\156\x2e");
        Pp:
        $this->issuer = trim($Q9[0]->textContent);
    }
    protected function parseNameIdPolicy(DOMElement $hB)
    {
        $kM = IDPUtilities::xpQuery($hB, "\56\x2f\163\141\x6d\154\137\160\x72\157\x74\x6f\x63\x6f\154\72\116\x61\x6d\x65\x49\x44\120\157\x6c\x69\x63\x79");
        if (!empty($kM)) {
            goto az;
        }
        return;
        az:
        $kM = $kM[0];
        if (!$kM->hasAttribute("\106\x6f\162\x6d\141\x74")) {
            goto Ow;
        }
        $this->nameIdPolicy["\x46\x6f\x72\155\x61\164"] = $kM->getAttribute("\106\x6f\x72\155\141\164");
        Ow:
        if (!$kM->hasAttribute("\123\x50\x4e\141\x6d\x65\121\165\141\x6c\151\x66\x69\x65\162")) {
            goto wT;
        }
        $this->nameIdPolicy["\x53\x50\x4e\x61\155\x65\121\x75\141\x6c\x69\146\151\145\162"] = $kM->getAttribute("\x53\x50\x4e\x61\x6d\x65\121\165\x61\x6c\151\x66\x69\145\x72");
        wT:
        if (!$kM->hasAttribute("\x41\x6c\x6c\x6f\167\x43\x72\x65\x61\x74\145")) {
            goto Xe;
        }
        $this->nameIdPolicy["\101\x6c\x6c\x6f\x77\103\162\145\x61\164\x65"] = IDPUtilities::parseBoolean($kM, "\x41\x6c\x6c\x6f\167\x43\162\145\141\x74\x65", false);
        Xe:
    }
    protected function parseRequestedAuthnContext(DOMElement $hB)
    {
        $bV = IDPUtilities::xpQuery($hB, "\56\57\x73\x61\155\x6c\x5f\160\x72\x6f\164\157\143\157\154\x3a\x52\145\161\x75\x65\x73\x74\145\144\x41\165\164\x68\x6e\x43\157\156\x74\145\x78\164");
        if (!empty($bV)) {
            goto gm;
        }
        return;
        gm:
        $bV = $bV[0];
        $T4 = array("\101\165\x74\x68\156\103\x6f\156\x74\145\x78\x74\103\154\x61\x73\x73\x52\x65\x66" => array(), "\103\x6f\155\x70\141\x72\x69\x73\x6f\x6e" => "\145\x78\141\x63\x74");
        $Zi = IDPUtilities::xpQuery($bV, "\56\57\163\x61\155\x6c\137\x61\163\163\x65\162\x74\151\x6f\x6e\x3a\101\x75\x74\x68\156\103\x6f\x6e\x74\x65\170\x74\x43\x6c\x61\163\163\122\145\146");
        foreach ($Zi as $c0) {
            $T4["\x41\165\x74\150\156\103\x6f\x6e\x74\145\170\x74\x43\x6c\141\163\163\x52\145\x66"][] = trim($c0->textContent);
            am:
        }
        Jk:
        if (!$bV->hasAttribute("\x43\157\x6d\x70\141\x72\151\x73\x6f\156")) {
            goto jM;
        }
        $T4["\103\157\x6d\x70\141\x72\x69\163\x6f\x6e"] = $bV->getAttribute("\x43\x6f\155\x70\x61\162\x69\163\x6f\x6e");
        jM:
        $this->requestedAuthnContext = $T4;
    }
    protected function parseScoping(DOMElement $hB)
    {
        $yO = IDPUtilities::xpQuery($hB, "\x2e\x2f\x73\x61\x6d\x6c\137\160\162\157\164\157\143\157\x6c\x3a\x53\143\157\x70\151\156\x67");
        if (!empty($yO)) {
            goto ZQ;
        }
        return;
        ZQ:
        $yO = $yO[0];
        if (!$yO->hasAttribute("\x50\x72\x6f\x78\x79\103\x6f\x75\156\x74")) {
            goto j5;
        }
        $this->ProxyCount = (int) $yO->getAttribute("\x50\x72\x6f\170\171\x43\157\x75\x6e\164");
        j5:
        $Ya = IDPUtilities::xpQuery($yO, "\56\x2f\163\x61\x6d\154\x5f\160\x72\x6f\x74\x6f\x63\x6f\154\x3a\111\104\x50\114\x69\x73\x74\x2f\x73\141\155\x6c\137\x70\162\x6f\164\157\x63\x6f\x6c\72\111\104\x50\105\156\x74\x72\x79");
        foreach ($Ya as $a9) {
            if ($a9->hasAttribute("\x50\162\157\x76\151\x64\145\x72\111\104")) {
                goto hI;
            }
            throw new Exception("\103\157\x75\154\144\40\156\x6f\x74\x20\x67\x65\x74\x20\120\x72\157\x76\x69\144\x65\162\x49\104\40\146\162\157\155\40\123\143\x6f\x70\x69\x6e\147\x2f\x49\104\120\x45\156\x74\x72\171\x20\x65\x6c\145\x6d\145\x6e\x74\40\x69\x6e\40\101\x75\164\x68\156\x52\x65\x71\x75\145\x73\164\40\157\x62\152\x65\143\164");
            hI:
            $this->IDPList[] = $a9->getAttribute("\x50\x72\x6f\166\x69\x64\145\162\111\x44");
            i_:
        }
        ie:
        $Hk = IDPUtilities::xpQuery($yO, "\56\57\x73\141\x6d\154\137\x70\162\x6f\x74\x6f\x63\157\154\x3a\x52\145\x71\165\145\163\164\145\162\111\104");
        foreach ($Hk as $oE) {
            $this->RequesterID[] = trim($oE->textContent);
            vu:
        }
        Xs:
    }
}
