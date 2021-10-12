<?php


class MiniorangeSAMLIdpSupport
{
    public $email;
    public $phone;
    public $query;
    public function __construct($ZK, $kx, $BJ)
    {
        $this->email = $ZK;
        $this->phone = $kx;
        $this->query = $BJ;
    }
    public function sendSupportQuery()
    {
        $this->query = "\x5b\x44\162\165\160\x61\x6c\55\x37\x20\123\x41\115\x4c\x20\111\x44\x50\x20\120\x72\145\x6d\x69\165\155\40\x4d\x6f\144\x75\x6c\145\x5d\x20" . $this->query;
        $xE = array("\143\x6f\155\160\x61\x6e\171" => $_SERVER["\x53\105\x52\126\105\122\x5f\x4e\101\x4d\105"], "\145\x6d\x61\x69\154" => $this->email, "\143\143\x45\155\x61\151\x6c" => "\x64\162\165\x70\x61\x6c\163\165\160\x70\157\162\164\x40\x78\145\x63\165\162\x69\146\171\x2e\x63\157\155", "\x70\150\157\156\145" => $this->phone, "\x71\x75\x65\162\x79" => $this->query, "\163\x75\x62\152\x65\143\x74" => "\104\162\x75\160\x61\154\55\x37\40\x53\101\115\114\40\x49\104\120\40\120\162\x65\x6d\151\x75\155\40\121\165\145\x72\171");
        $Ez = json_encode($xE);
        $zi = MiniorangeSAMLIdpConstants::BASE_URL . "\57\x6d\x6f\141\x73\x2f\x72\145\x73\x74\x2f\143\165\x73\x74\x6f\155\145\162\57\143\x6f\x6e\164\x61\143\164\x2d\165\x73";
        $yG = curl_init($zi);
        curl_setopt($yG, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($yG, CURLOPT_ENCODING, '');
        curl_setopt($yG, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($yG, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($yG, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($yG, CURLOPT_MAXREDIRS, 10);
        curl_setopt($yG, CURLOPT_HTTPHEADER, array("\x43\x6f\x6e\x74\x65\156\164\x2d\x54\x79\x70\145\72\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\156\x2f\152\163\157\x6e", "\143\x68\141\x72\163\145\164\x3a\40\125\124\x46\x2d\x38", "\101\165\164\150\157\162\x69\x7a\141\x74\x69\x6f\x6e\x3a\40\x42\141\x73\x69\x63"));
        curl_setopt($yG, CURLOPT_POST, TRUE);
        curl_setopt($yG, CURLOPT_POSTFIELDS, $Ez);
        $ES = curl_exec($yG);
        if (!curl_errno($yG)) {
            goto xe;
        }
        $D6 = array("\x25\x6d\x65\x74\x68\x6f\144" => "\x73\145\x6e\144\123\165\160\x70\x6f\x72\164\121\165\145\x72\x79", "\x25\146\151\154\x65" => "\x6d\151\156\x69\x6f\162\141\x6e\147\x65\137\x73\x61\155\154\x5f\151\x64\x70\137\x73\x75\160\x70\x6f\162\164\x2e\x70\x68\x70", "\45\145\x72\162\157\x72" => curl_error($yG));
        watchdog("\x6d\151\x6e\x69\157\x72\141\156\147\145\137\x73\x61\155\x6c\x5f\x69\x64\x70", "\x63\x55\x52\x4c\40\x45\x72\x72\x6f\x72\x20\141\164\x20\x25\155\145\x74\150\157\144\x20\x6f\x66\40\45\146\x69\154\145\72\40\45\x65\162\x72\x6f\x72", $D6);
        return FALSE;
        xe:
        curl_close($yG);
        return TRUE;
    }
}
