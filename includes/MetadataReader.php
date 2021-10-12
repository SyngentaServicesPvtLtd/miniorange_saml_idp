<?php


class MetadataReader
{
    private $serviceProviders;
    public function __construct(\DOMNode $hB = NULL)
    {
        $this->serviceProviders = array();
        $Wv = IDPUtilities::xpQuery($hB, "\x2e\57\163\x61\x6d\x6c\x5f\155\145\x74\141\x64\x61\164\x61\x3a\x45\156\164\x69\164\171\x44\x65\x73\143\x72\151\x70\x74\x6f\162");
        foreach ($Wv as $XW) {
            $wA = IDPUtilities::xpQuery($XW, "\x2e\x2f\163\141\x6d\154\137\155\x65\164\x61\144\141\x74\141\x3a\123\120\123\123\117\x44\145\163\x63\162\151\x70\x74\x6f\162");
            if (!(isset($wA) && !empty($wA))) {
                goto cL;
            }
            array_push($this->serviceProviders, new ServiceProviders($XW));
            cL:
            p5:
        }
        yv:
    }
    public function getServiceProviders()
    {
        return $this->serviceProviders;
    }
}
class ServiceProviders
{
    private $entityID;
    private $acsURL;
    private $logoutDetails;
    private $assertionsSigned;
    private $signingCertificate;
    public function __construct(\DOMElement $hB = NULL)
    {
        $this->signingCertificate = array();
        $this->logoutDetails = array();
        if (!$hB->hasAttribute("\x65\x6e\x74\151\164\x79\x49\x44")) {
            goto CH;
        }
        $this->entityID = $hB->getAttribute("\145\x6e\x74\x69\x74\x79\x49\x44");
        CH:
        $wA = IDPUtilities::xpQuery($hB, "\56\x2f\x73\141\155\x6c\137\155\145\x74\x61\x64\141\x74\x61\72\123\120\x53\123\117\x44\x65\163\143\162\151\160\x74\x6f\162");
        if (count($wA) > 1) {
            goto Ue;
        }
        if (empty($wA)) {
            goto RQ;
        }
        goto n0;
        Ue:
        throw new Exception("\x4d\157\x72\145\40\x74\150\x61\156\x20\x6f\156\x65\40\74\x53\120\x53\123\117\x44\x65\x73\143\x72\x69\x70\164\157\x72\x3e\40\x69\156\40\x3c\x45\156\164\151\164\x79\x44\145\163\143\x72\x69\160\x74\x6f\x72\76\x2e");
        goto n0;
        RQ:
        throw new Exception("\x4d\x69\x73\x73\151\x6e\147\40\x72\x65\161\x75\x69\162\x65\x64\40\74\x53\x50\x53\123\117\104\x65\x73\143\x72\x69\x70\x74\x6f\162\76\40\x69\x6e\x20\74\x45\x6e\164\151\x74\171\x44\x65\163\143\162\151\160\164\157\162\76\56");
        n0:
        $this->parseAcsURL($wA);
        $this->parseLogoutURL($wA);
        $this->assertionsSigned($wA);
        $this->parsex509Certificate($wA);
    }
    private function parsex509Certificate($hB)
    {
        $CM = IDPUtilities::xpQuery($hB[0], "\x2e\x2f\163\x61\155\x6c\137\x6d\x65\x74\141\144\141\x74\x61\x3a\x4b\145\x79\104\x65\163\x63\162\x69\x70\x74\x6f\x72");
        foreach ($CM as $vr) {
            if ($vr->hasAttribute("\x75\x73\145")) {
                goto DS;
            }
            $this->parseSigningCertificate($vr);
            goto D6;
            DS:
            if (!($vr->getAttribute("\165\163\x65") == "\163\151\x67\x6e\151\x6e\x67")) {
                goto BR;
            }
            $this->parseSigningCertificate($vr);
            BR:
            D6:
            OU:
        }
        DH:
    }
    private function parseSigningCertificate($hB)
    {
        $q3 = IDPUtilities::xpQuery($hB, "\x2e\x2f\144\163\72\113\145\171\111\156\146\157\57\x64\x73\72\130\65\x30\x39\x44\141\x74\x61\x2f\x64\163\x3a\130\65\60\71\x43\145\x72\x74\x69\x66\x69\143\x61\x74\x65");
        $R1 = trim($q3[0]->textContent);
        $R1 = str_replace(array("\xd", "\xa", "\11", "\40"), '', $R1);
        if (empty($q3)) {
            goto xC;
        }
        $this->signingCertificate = IDPUtilities::sanitize_certificate($R1);
        xC:
    }
    private function parseAcsURL($wA)
    {
        $H8 = IDPUtilities::xpQuery($wA[0], "\x2e\57\x73\141\155\154\137\x6d\x65\164\x61\144\x61\164\141\x3a\101\163\163\145\x72\164\151\157\x6e\x43\157\156\163\x75\155\x65\x72\123\x65\162\x76\x69\143\x65");
        foreach ($H8 as $LI) {
            if (!$LI->hasAttribute("\114\157\143\x61\164\151\x6f\156")) {
                goto Pq;
            }
            $this->acsURL = $LI->getAttribute("\x4c\157\x63\x61\x74\x69\157\156");
            Pq:
            Jm:
        }
        wR:
    }
    private function assertionsSigned($wA)
    {
        foreach ($wA as $LI) {
            if (!$LI->hasAttribute("\127\x61\x6e\x74\101\x73\163\x65\x72\164\x69\x6f\x6e\x73\123\x69\x67\156\x65\x64")) {
                goto yg;
            }
            $this->assertionsSigned = $LI->getAttribute("\127\x61\156\164\101\x73\163\x65\x72\164\x69\x6f\x6e\163\x53\x69\147\x6e\x65\144");
            yg:
            hT:
        }
        yU:
    }
    private function parseLogoutURL($hB)
    {
        $op = IDPUtilities::xpQuery($hB[0], "\56\x2f\x73\141\155\x6c\x5f\155\145\164\x61\144\141\x74\141\x3a\123\151\x6e\x67\154\x65\114\x6f\147\157\x75\164\123\x65\162\166\x69\x63\145");
        foreach ($op as $ko) {
            $qw = str_replace("\x75\x72\x6e\72\157\141\x73\x69\163\x3a\x6e\x61\x6d\145\x73\72\164\143\x3a\123\101\x4d\x4c\x3a\62\56\x30\72\142\x69\x6e\x64\x69\x6e\x67\163\72", '', $ko->getAttribute("\x42\x69\x6e\144\x69\156\147"));
            $this->logoutDetails = array_merge($this->logoutDetails, array($qw => $ko->getAttribute("\114\x6f\x63\141\x74\x69\x6f\156")));
            GG:
        }
        HA:
    }
    public function getEntityID()
    {
        return $this->entityID;
    }
    public function getAcsURL()
    {
        return $this->acsURL;
    }
    public function getAssertionsSigned()
    {
        return $this->assertionsSigned;
    }
    public function getSigningCertificate()
    {
        return $this->signingCertificate;
    }
    public function getLogoutURL($qw)
    {
        return isset($this->logoutDetails[$qw]) ? $this->logoutDetails[$qw] : '';
    }
}
