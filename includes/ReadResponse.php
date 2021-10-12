<?php


include "\x41\x73\163\x65\162\x74\151\x6f\x6e\56\x70\x68\x70";
class SAML2_Response
{
    private $assertions;
    private $destination;
    public function __construct(DOMElement $hB = NULL)
    {
        $this->assertions = array();
        if (!($hB === NULL)) {
            goto NC;
        }
        return;
        NC:
        if (!$hB->hasAttribute("\x44\145\163\x74\x69\x6e\141\x74\151\157\x6e")) {
            goto dB;
        }
        $this->destination = $hB->getAttribute("\104\x65\x73\x74\151\x6e\x61\x74\151\x6f\x6e");
        dB:
        $li = $hB->firstChild;
        a9:
        if (!($li !== NULL)) {
            goto aT;
        }
        if (!($li->namespaceURI !== "\165\x72\156\72\x6f\141\163\151\163\72\156\141\155\145\163\72\164\143\x3a\123\x41\115\x4c\72\62\x2e\60\72\x61\163\x73\x65\162\x74\x69\157\x6e")) {
            goto pz;
        }
        goto G6;
        pz:
        if (!($li->localName === "\x41\163\x73\145\162\164\x69\157\x6e" || $li->localName === "\105\156\143\x72\171\160\x74\x65\144\x41\x73\x73\145\x72\x74\151\x6f\x6e")) {
            goto NZ;
        }
        $this->assertions[] = new SAML2_Assertion($li);
        NZ:
        G6:
        $li = $li->nextSibling;
        goto a9;
        aT:
    }
    public function getAssertions()
    {
        return $this->assertions;
    }
    public function setAssertions(array $Cj)
    {
        $this->assertions = $Cj;
    }
    public function getDestination()
    {
        return $this->destination;
    }
    public function toUnsignedXML()
    {
        $L0 = parent::toUnsignedXML();
        foreach ($this->assertions as $Jr) {
            $Jr->toXML($L0);
            KK:
        }
        G5:
        return $L0;
    }
}
