<?php


function miniorange_saml_idp_export_config($form, &$form_state)
{
    drupal_add_css(drupal_get_path("\x6d\157\144\x75\154\x65", "\x6d\x69\156\151\x6f\x72\141\x6e\147\x65\x5f\163\x61\155\x6c\x5f\x69\x64\x70") . "\x2f\143\x73\x73\x2f\x62\x6f\x6f\x74\163\x74\x72\141\160\56\155\151\x6e\x2e\x63\163\x73", array("\x67\x72\x6f\x75\160" => CSS_DEFAULT, "\x65\166\x65\x72\x79\137\160\x61\147\x65" => FALSE));
    drupal_add_css(drupal_get_path("\155\x6f\x64\x75\x6c\145", "\x6d\151\x6e\151\x6f\x72\x61\156\x67\x65\137\163\x61\x6d\154\137\x69\x64\160") . "\x2f\143\163\163\57\x73\164\171\154\x65\x5f\x73\x65\164\164\151\x6e\147\x73\x2e\143\x73\x73", array("\147\x72\x6f\165\x70" => CSS_DEFAULT, "\x65\166\x65\x72\x79\x5f\160\141\147\145" => FALSE));
    global $base_url;
    $ZZ = Utilities::isCustomer_registered($form, $form_state);
    if (!(variable_get("\155\x69\156\151\157\162\141\156\147\145\137\x73\141\155\154\137\154\x69\143\x65\156\163\x65\137\x6b\145\171", NULL) == NULL && variable_get("\155\151\156\x69\x6f\x72\141\156\147\x65\137\x73\141\x6d\x6c\x5f\143\165\x73\x74\x6f\155\x65\x72\137\x61\x64\x6d\151\x6e\x5f\x65\155\x61\x69\154", NULL) != NULL)) {
        goto dH;
    }
    return $form;
    dH:
    $form["\x68\145\x61\x64\145\162\x5f\x74\x6f\x70\137\x73\x74\171\x6c\x65\x5f\61"] = array("\43\x6d\x61\x72\153\x75\160" => "\x3c\x64\151\166\x20\x63\x6c\x61\163\163\75\42\x6d\157\x5f\x73\141\x6d\x6c\137\164\x61\142\x6c\145\x5f\154\x61\171\157\165\164\137\61\42\76");
    $form["\150\145\141\x64\145\162\137\164\157\160\137\x73\x74\x79\154\x65\x5f\x74\x6f\160\163"] = array("\43\x6d\x61\162\153\165\x70" => "\x3c\144\x69\x76\x20\x63\154\141\x73\x73\x3d\x22\155\157\137\163\141\155\x6c\137\x74\141\x62\154\145\x5f\x6c\141\x79\x6f\165\164\x20\155\x6f\137\x73\141\x6d\x6c\x5f\143\x6f\156\x74\141\x69\x6e\x65\162\42\x3e");
    $form["\155\141\162\153\165\x70\x5f\164\x6f\x70\137\x68\x65\141\x64"] = array("\43\155\x61\x72\x6b\165\x70" => "\74\142\x3e\74\x73\x70\141\x6e\x20\163\164\171\154\x65\x3d\x22\x66\x6f\156\164\x2d\x73\151\x7a\x65\72\40\x31\x37\160\x78\x3b\x22\76\x49\x4d\120\x4f\122\x54\x2f\105\130\120\117\x52\124\40\103\117\x4e\x46\x49\x47\125\122\101\124\x49\x4f\116\x53\x3c\x2f\163\160\141\x6e\x3e\74\57\142\76\74\142\162\76\74\x62\x72\76\x3c\150\x72\x3e\74\x62\x72\x2f\x3e");
    $form["\x6d\141\162\153\x75\x70\x5f\x31"] = array("\x23\155\x61\162\153\x75\160" => "\74\x64\x69\166\40\143\154\141\163\163\x3d\42\155\x6f\x5f\x73\x61\155\154\x5f\150\x69\147\x68\154\x69\147\x68\164\x5f\142\x61\143\153\147\x72\157\x75\x6e\x64\137\156\x6f\164\x65\42\40\163\x74\171\x6c\145\x3d\42\x77\x69\144\x74\x68\x3a\40\x39\67\x25\42\x3e\x3c\x70\76\74\142\x3e\x4e\x4f\124\x45\x3a\40\74\x2f\x62\x3e\124\150\151\x73\x20\x74\141\x62\40\x77\x69\x6c\154\40\x68\x65\x6c\160\40\171\157\x75\x20\x74\x6f\40\164\x72\141\156\x73\146\145\162\40\x79\x6f\x75\162\x20\x6d\157\144\x75\154\x65\40\x63\x6f\x6e\x66\x69\x67\x75\162\x61\164\151\157\156\163\40\167\150\145\156\40\171\x6f\x75\40\143\150\141\x6e\x67\x65\x20\171\157\165\162\x20\x44\162\x75\x70\x61\154\40\x69\156\163\164\141\x6e\143\145\56\x20\12\x20\40\x20\40\x20\x20\40\x20\x20\x20\40\x20\x20\x20\40\40\x20\x20\x20\x20\40\40\x20\x20\74\142\x72\x3e\x45\x78\x61\x6d\x70\x6c\x65\x3a\40\x57\x68\x65\x6e\40\x79\157\165\x20\x73\x77\x69\x74\143\x68\x20\146\162\x6f\155\x20\164\145\x73\164\40\x65\156\x76\x69\x72\x6f\x6e\155\x65\x6e\164\x20\x74\x6f\40\160\x72\157\144\165\143\164\x69\157\x6e\56\x3c\x62\162\x3e\106\x6f\x6c\x6c\x6f\167\x20\164\150\x65\x73\145\40\x33\x20\163\x69\x6d\160\x6c\x65\x20\x73\x74\x65\x70\163\40\x74\157\40\x64\x6f\40\x74\150\141\164\x3a\x3c\142\162\76\12\40\x20\x20\x20\40\x20\x20\x20\40\40\x20\x20\40\x20\40\40\40\x20\40\40\40\x20\40\40\74\142\162\x3e\x31\56\x20\104\x6f\x77\156\x6c\x6f\x61\144\40\155\157\x64\165\x6c\145\40\143\x6f\156\x66\151\147\165\x72\x61\164\151\157\x6e\x20\x66\151\154\x65\40\142\x79\40\143\x6c\x69\x63\x6b\x69\x6e\x67\40\x6f\156\40\164\150\145\40\104\157\x77\x6e\154\x6f\x61\x64\40\x6d\x6f\x64\165\x6c\x65\40\103\x6f\156\146\x69\147\165\162\x61\x74\x69\157\x6e\40\x62\x75\164\164\157\x6e\40\x67\x69\166\145\x6e\40\x62\145\154\x6f\x77\x2e\12\x20\x20\40\x20\40\x20\40\x20\40\40\x20\40\40\x20\40\40\40\x20\40\40\x20\x20\40\40\74\142\x72\x3e\x32\56\x20\111\156\x73\164\x61\154\x6c\40\164\150\145\x20\155\157\144\165\x6c\x65\40\x6f\x6e\x20\156\x65\x77\x20\104\162\x75\x70\141\x6c\x20\x69\x6e\163\x74\x61\156\143\145\x2e\74\142\162\76\x33\x2e\40\x55\x70\154\x6f\141\x64\x20\x74\x68\145\40\x63\x6f\x6e\x66\x69\147\x75\x72\x61\x74\x69\x6f\x6e\40\146\151\154\145\40\151\x6e\40\x49\155\x70\157\x72\164\40\115\x6f\x64\165\x6c\145\40\x43\x6f\x6e\146\x69\147\x75\x72\x61\164\x69\157\156\x73\x20\x73\x65\x63\x74\x69\x6f\x6e\x2e\74\142\162\x3e\12\40\40\x20\x20\40\x20\40\x20\40\x20\40\40\40\x20\40\40\x20\40\40\40\x20\x20\40\40\x3c\x62\162\x3e\x3c\x62\x3e\x43\x68\157\157\163\145\x20\42\x6a\x73\157\x6e\42\x20\105\x78\164\x65\x6e\x65\x64\x20\x6d\x6f\x64\165\x6c\x65\x20\143\157\x6e\x66\151\147\165\162\141\164\x69\157\156\40\146\x69\154\145\x20\x61\156\144\x20\165\x70\x6c\157\141\144\x20\142\x79\40\x63\154\x69\x63\x6b\151\156\147\x20\157\156\40\x74\x68\145\x20\x62\165\164\164\157\x6e\x20\147\x69\166\x65\x6e\x20\142\x65\x6c\157\167\56\74\57\x62\76\x3c\x62\x72\x3e\xa\40\x20\40\40\x20\x20\x20\x20\x20\40\40\x20\40\40\40\x20\40\40\x20\40\40\40\40\40\x41\156\144\x20\x6a\165\x73\x74\40\154\x69\153\145\x20\164\x68\141\164\54\x20\x61\154\x6c\x20\171\157\165\162\x20\x6d\157\x64\165\x6c\x65\40\143\x6f\156\146\151\147\x75\x72\141\164\151\157\156\163\40\x77\x69\x6c\154\40\x62\145\x20\164\x72\141\x6e\163\x66\145\162\x72\145\x64\x21\40\131\157\x75\x20\x63\x61\x6e\40\141\154\x73\x6f\40\x73\145\x6e\x64\x20\165\x73\40\x74\150\151\163\x20\x66\x69\x6c\x65\40\141\154\x6f\156\x67\x20\167\x69\164\x68\x20\171\157\165\x72\40\163\165\x70\x70\157\x72\x74\x20\x71\165\145\x72\x79\x2e\74\x2f\x70\x3e\74\x2f\x64\x69\166\x3e");
    $form["\155\x61\162\x6b\165\160\137\144\151\x76\x5f\x69\155\x70\x31"] = array("\43\155\141\x72\x6b\165\x70" => "\x3c\x64\151\166\x20\x69\x64\75\x22\155\157\163\141\x6d\154\137\x76\x74\x5f\151\155\160\157\162\x74\x22\x3e");
    $form["\155\x69\156\151\x6f\x72\141\156\147\145\x5f\x69\x64\x70\137\147\165\x69\144\145\x5f\x6c\x69\x6e\x6b\137\143\157\156\164\141\151\x6e\145\162"] = array("\x23\155\x61\162\x6b\165\160" => "\x3c\142\162\76\x3c\x62\x72\76\74\144\151\166\40\x63\x6c\141\163\x73\x3d\x22\x6d\157\137\x73\141\155\154\137\164\x61\144\x62\x6c\x65\x5f\154\141\171\x6f\x75\x74\40\x6d\157\x5f\x73\x61\155\154\137\x63\157\x6e\164\141\x69\156\145\162\x5f\x33\x22\x20\163\x74\x79\154\145\x3d\42\164\145\170\x74\55\141\154\151\147\156\72\x20\x63\x65\x6e\164\x65\x72\x3b\146\154\x6f\141\x74\x3a\x20\x6c\145\146\x74\x3b\x6d\141\162\147\151\x6e\x2d\162\151\x67\x68\x74\x3a\40\x32\x30\x70\170\x3b\x62\157\x72\144\145\x72\x3a\x20\163\x6f\154\x69\144\40\x31\160\170\x20\43\60\60\60\x30\60\60\x32\x34\x3b\160\x61\x64\144\151\x6e\x67\55\142\157\x74\x74\x6f\155\x3a\40\65\60\160\x78\x3b\42\x3e");
    $form["\155\157\137\x6d\x61\x72\x6b\165\160\137\144\151\x76"] = array("\x23\x6d\141\162\153\x75\160" => "\74\144\151\166\x20\x69\x64\x3d\x22\155\157\163\141\x6d\x6c\137\166\x74\137\151\x6d\x70\145\170\x70\42\x3e");
    $form["\155\x6f\x5f\x6d\141\x72\153\165\x70\137\x74\x6f\x70"] = array("\43\155\141\x72\153\165\x70" => "\x3c\142\x3e\74\163\160\141\156\40\163\164\171\x6c\x65\x3d\42\146\157\156\x74\x2d\163\x69\x7a\145\72\x20\61\67\x70\x78\x3b\x22\x3e\105\x58\120\x4f\x52\x54\40\103\x4f\x4e\106\111\107\125\x52\x41\124\111\117\x4e\74\x2f\x73\160\x61\x6e\x3e\74\57\142\x3e\74\x62\162\76\74\142\162\76\x3c\150\x72\x3e\74\x62\x72\57\76\x3c\142\x72\x3e");
    if (miniorange_saml_is_sp_configured()) {
        goto eJ;
    }
    $form["\x6d\151\x6e\151\157\162\x61\156\x67\145\137\163\x61\x6d\154\x5f\151\x64\160\137\x65\x78\x70\157\162\x74"] = array("\x23\155\x61\162\x6b\165\x70" => "\74\144\151\166\x20\163\164\171\x6c\x65\75\42\144\151\163\x70\154\141\x79\x3a\x62\x6c\x6f\143\153\73\x20\155\141\x72\x67\x69\156\55\x74\x6f\x70\72\x31\x30\160\170\x3b\40\143\157\154\157\x72\x3a\162\145\x64\73\40\x62\141\x63\153\147\162\157\165\x6e\x64\x2d\x63\157\x6c\x6f\x72\72\x72\x67\142\x61\x28\62\65\61\x2c\40\x32\63\x32\54\40\60\x2c\x20\60\x2e\x31\65\51\73\40\x66\x6f\x6e\x74\55\x73\x69\x7a\x65\72\40\x6d\x65\144\x69\x75\x6d\73\x70\x61\144\144\151\156\147\72\x35\x70\x78\73\x62\157\162\144\x65\x72\72\163\x6f\x6c\151\x64\40\x31\x70\x78\x20\162\147\x62\141\x28\62\65\65\x2c\x20\60\54\x20\71\x2c\40\60\x2e\x33\66\x29\x3b\x22\76\12\x9\40\x20\40\x20\x20\40\40\40\x20\x20\40\40\x20\40\40\x20\40\40\x20\40\x20\x20\40\x20\x20\40\40\40\x50\154\145\141\x73\145\40\x3c\141\40\150\x72\145\x66\x3d\x22" . $base_url . "\57\141\x64\x6d\151\156\x2f\143\157\156\x66\151\x67\57\x70\x65\157\x70\154\x65\x2f\x6d\x69\x6e\x69\x6f\162\141\156\x67\145\137\163\141\155\x6c\x5f\151\144\x70\57\151\144\x70\137\163\145\164\x75\160\42\76\143\x6f\156\146\151\x67\165\x72\x65\40\164\x68\x65\x20\155\x6f\144\165\x6c\145\74\57\141\76\x20\x66\151\x72\163\164\40\x74\157\x20\145\x78\x70\157\162\x74\x20\x74\150\x65\40\x63\157\x6e\146\x69\147\x75\x72\x61\x74\151\x6f\156\163\x2e\12\40\40\40\40\40\40\x20\40\x20\40\x20\40\x20\40\40\40\40\x20\x20\x20\40\x20\x20\40\40\40\74\x2f\x64\151\x76\x3e");
    goto rE;
    eJ:
    $form["\155\x69\156\151\157\162\x61\156\x67\x65\x5f\x73\141\155\154\137\x69\x64\160\x5f\145\170\x70\x6f\x72\x74"] = array("\x23\x74\x79\x70\x65" => "\x73\165\x62\155\x69\164", "\43\166\x61\x6c\165\145" => t("\x44\157\x77\x6e\154\x6f\x61\x64\x20\115\x6f\x64\165\x6c\x65\x20\103\x6f\x6e\146\151\x67\165\162\141\164\151\x6f\x6e"), "\43\160\162\145\x66\151\x78" => "\x3c\164\144\x3e", "\43\x73\x75\146\146\151\170" => "\74\57\x74\x64\76", "\43\x73\x75\x62\155\x69\164" => array("\x6d\x69\x6e\x69\x6f\162\x61\156\147\145\x5f\x69\155\160\x6f\x72\x74\x5f\145\x78\x70\x6f\162\164"), "\x23\x61\164\164\162\151\142\165\x74\145\163" => array("\151\x64" => "\155\x6f\163\x61\x6d\154\137\166\x74\137\x65\170\x70\x6f\162\x74", "\x73\x74\x79\x6c\145" => "\142\157\162\x64\145\162\55\162\x61\x64\x69\165\163\72\64\x70\170\73\167\151\144\164\150\72\67\67\45\x3b\142\141\x63\153\x67\162\157\x75\x6e\x64\72\x20\43\63\x33\67\141\142\67\x3b\143\x6f\x6c\x6f\x72\x3a\40\x23\x66\x66\146\146\146\146\x3b\x74\145\170\x74\x2d\163\150\x61\144\x6f\167\x3a\40\60\x20\55\x31\x70\x78\40\61\160\x78\40\x23\63\x33\x37\141\142\67\x2c\x20\61\x70\170\40\x30\40\x31\160\170\40\43\x33\63\x37\141\x62\x37\54\40\60\40\61\x70\x78\x20\x31\160\170\x20\x23\x33\x33\x37\141\142\x37\x2c\40\55\x31\160\x78\x20\x30\40\61\160\170\x20\x23\x33\63\x37\x61\x62\67\73\142\x6f\170\x2d\x73\x68\141\144\x6f\167\x3a\40\x30\x20\61\160\x78\40\x30\40\x23\63\x33\67\141\x62\x37\73\142\x6f\162\x64\x65\162\x2d\x63\157\154\x6f\x72\72\40\43\63\x33\x37\x61\142\x37\x20\43\x33\63\67\141\142\67\40\43\63\63\67\141\142\x37\73"));
    rE:
    $form["\155\157\137\x6d\x61\x72\153\165\x70\x5f\x74\145\x73\164\137\144\151\x76"] = array("\x23\x6d\x61\162\153\165\160" => "\74\x2f\x64\151\x76\x3e\74\x2f\x64\x69\x76\x3e");
    $form["\x6d\151\156\151\157\162\141\x6e\x67\x65\x5f\151\x64\160\137\147\x75\x69\x64\145\x5f\154\151\156\153\137\x63\157\x6e\164"] = array("\43\155\x61\162\153\165\160" => "\74\x64\x69\x76\x20\143\x6c\141\163\163\75\42\x6d\x6f\x5f\163\x61\155\x6c\137\164\141\144\142\x6c\x65\x5f\x6c\141\171\157\x75\x74\40\155\x6f\x5f\x73\x61\155\154\137\143\157\x6e\x74\141\151\x6e\145\x72\x5f\63\x22\x20\163\164\x79\x6c\145\x3d\x22\x66\154\x6f\141\x74\x3a\x20\x6c\x65\x66\164\x3b\x74\x65\170\164\x2d\141\x6c\151\x67\156\72\x63\145\x6e\x74\145\162\73\x70\141\x64\x64\151\156\x67\55\142\x6f\x74\164\x6f\x6d\72\x20\x32\x30\x70\x78\73\x62\157\162\x64\145\162\72\x20\x73\x6f\x6c\x69\x64\x20\61\160\x78\x20\x23\60\60\60\x30\60\60\x32\x34\x3b\x3b\x22\76");
    $form["\155\157\x5f\x6d\x61\x72\153\x75\160\137\151\155\x70\157\x72\164"] = array("\43\155\x61\x72\153\x75\160" => "\x3c\142\x3e\x3c\x73\x70\141\x6e\x20\x73\x74\x79\154\145\x3d\42\x66\x6f\x6e\x74\x2d\163\x69\x7a\x65\x3a\40\x31\x37\x70\x78\x3b\x22\76\111\x4d\x50\117\x52\124\x20\103\117\116\x46\x49\x47\x55\122\x41\124\x49\117\116\x20\74\x2f\x73\160\x61\x6e\x3e\x3c\57\142\76\x3c\x62\x72\76\x3c\x62\162\x3e\x3c\150\162\x3e\74\142\x72\x3e");
    $form["\155\x6f\x5f\151\x6d\x70\x6f\x72\x74\x5f\103\x6f\x6e\x66\x69\x67\137\146\151\x6c\x65"] = array("\43\164\x79\160\x65" => "\146\x69\154\145", "\x23\x64\151\x73\x61\142\154\x65\144" => $ZZ, "\x23\x61\164\164\x72\x69\142\165\164\x65\163" => array("\151\x64" => "\x6d\157\163\141\155\x6c\137\166\x74\x5f\x69\155\160\x6f\162\x74", "\163\164\x79\x6c\145" => "\167\x69\144\x74\150\72\40\61\67\65\160\170\73"));
    $form["\x6d\151\x6e\x69\157\162\x61\156\147\x65\x5f\x73\x61\155\x6c\x5f\151\144\160\137\x69\x6d\160\x6f\162\x74\x5f\143\x6f\156\146\x69\147"] = array("\x23\x74\171\160\x65" => "\163\165\142\x6d\151\164", "\43\x76\141\154\165\x65" => t("\125\x70\x6c\157\141\x64"), "\x23\163\165\142\155\151\164" => array("\155\x69\156\x69\157\x72\x61\156\x67\x65\137\x69\155\160\157\x72\164\x5f\103\157\156\146\x69\147"), "\x23\x64\151\163\x61\x62\154\145\144" => $ZZ, "\43\141\164\164\162\x69\x62\x75\x74\x65\163" => array("\x69\x64" => "\x6d\x6f\x73\x61\155\154\137\166\164\x5f\145\x78\160\157\x72\164", "\x73\x74\171\154\145" => "\142\x6f\x72\x64\x65\x72\x2d\162\x61\x64\x69\x75\x73\72\64\160\x78\x3b\167\151\144\x74\x68\x3a\61\60\60\x70\x78\73\142\x61\143\x6b\x67\162\157\x75\x6e\x64\72\x20\43\63\x33\x37\x61\142\x37\73\143\157\x6c\x6f\162\72\x20\43\x66\146\146\x66\146\146\x3b\164\145\x78\x74\x2d\163\x68\x61\144\x6f\x77\72\x20\60\40\55\61\160\x78\x20\x31\x70\170\40\x23\63\63\67\x61\x62\67\54\x20\61\160\x78\x20\x30\x20\x31\160\x78\40\43\63\x33\x37\141\142\x37\54\40\60\x20\x31\160\x78\40\61\x70\x78\x20\43\x33\x33\67\x61\142\x37\54\x20\55\61\160\170\x20\60\x20\x31\160\x78\40\x23\63\63\67\141\142\x37\x3b\x62\x6f\170\55\x73\x68\141\x64\x6f\x77\x3a\40\60\x20\61\x70\x78\x20\x30\x20\x23\63\63\67\141\x62\x37\73\x62\157\x72\x64\145\162\x2d\x63\x6f\x6c\157\x72\x3a\40\43\x33\x33\x37\141\142\x37\x20\43\63\x33\x37\141\142\67\40\x23\x33\x33\67\141\x62\67\73\73\x6d\x61\162\147\151\156\x2d\x74\157\160\72\x20\55\64\x37\x70\x78\73"));
    $form["\x6d\157\x5f\x6d\141\x72\x6b\x75\x73\x70\137\164\145\x73\164\137\144\x69\x76"] = array("\43\155\x61\162\153\x75\x70" => "\74\x2f\x64\151\x76\76");
    $form["\x6d\x6f\137\155\x61\x72\153\x75\x70\137\x69\x64\160\x5f\x61\x74\x74\162\137\x68\145\x61\x64\x65\x72\137\164\157\160\x5f\144\151\x76\x5f\x63\x6c\157\163\x65"] = array("\43\155\141\x72\153\x75\160" => "\74\57\x64\x69\x76\76\x3c\57\144\x69\x76\x3e");
    Utilities::AddsupportTab($form, $form_state);
    $form["\155\157\x5f\x6d\141\162\153\165\x70\137\x69\144\160\137\x63\x6c\157\x73\x73\145\x5f\x64\x69\166"] = array("\x23\x6d\x61\162\153\x75\160" => "\74\x2f\x64\151\166\x3e");
    return $form;
}
function miniorange_saml_is_sp_configured()
{
    $fK = variable_get("\x6d\x69\x6e\151\x6f\162\141\156\147\x65\137\x73\141\x6d\x6c\x5f\151\144\x70\x5f\x61\x63\x73\x5f\x75\162\x6c");
    $I1 = variable_get("\x6d\x69\156\x69\x6f\162\141\156\x67\145\x5f\163\141\155\154\137\151\144\x70\x5f\x73\160\x5f\x65\x6e\x74\151\164\x79\137\151\144");
    if (!empty($fK) && !empty($I1)) {
        goto Lo;
    }
    return 0;
    goto n0;
    Lo:
    return 1;
    n0:
}
function miniorange_import_export()
{
    $r3 = array("\111\x44\x50\x5f\x4d\145\164\141\x64\x61\x74\x61" => "\x6d\x6f\x5f\x6f\160\x74\x69\x6f\x6e\x73\137\145\x6e\x75\155\137\x69\x64\145\x6e\x74\x69\164\171\x5f\x70\x72\157\166\x69\x64\145\x72", "\123\x65\x72\166\x69\x63\145\137\x50\162\x6f\166\x69\x64\x65\x72" => "\155\157\137\157\x70\164\x69\x6f\156\x73\x5f\x65\156\x75\x6d\x5f\x73\x65\162\166\x69\x63\x65\x5f\x70\x72\x6f\x76\151\x64\x65\x72", "\x41\x74\164\x72\151\142\165\x74\x65\137\115\141\x70\160\x69\156\147" => "\x6d\157\x5f\157\160\164\151\157\x6e\163\x5f\x61\164\164\162\151\x62\165\164\x65\137\155\141\160\x70\x69\x6e\x67", "\123\151\x67\x6e\x5f\x49\156\137\123\x65\164\164\x69\x6e\147\163" => "\x6d\157\137\x6f\160\x74\151\157\156\x73\137\163\151\147\156\151\156\137\163\x65\164\x74\156\x67\x73", "\x43\165\x73\164\157\155\x5f\x43\145\162\164\151\146\151\143\141\x74\145" => "\155\157\x5f\x6f\160\164\151\157\156\163\137\143\165\163\164\x6f\155\x5f\x63\x65\x72\x74\151\146\151\x63\141\164\x65");
    $Aq = array();
    foreach ($r3 as $p1 => $OK) {
        $Aq[$p1] = mo_get_configuration_array($OK);
        zz:
    }
    b_:
    $Aq["\x56\145\x72\163\x69\x6f\156\x5f\144\145\x70\x65\156\144\145\x6e\x63\x69\145\163"] = mo_get_version_informations();
    header("\103\157\156\x74\145\x6e\x74\55\x44\x69\x73\x70\157\163\151\x74\151\157\156\x3a\40\141\x74\x74\141\143\150\155\145\156\164\x3b\40\146\151\154\145\x6e\141\x6d\x65\75\x6d\x69\x6e\151\157\162\141\156\x67\x65\55\163\x61\x6d\x6c\55\x69\144\x70\55\143\157\x6e\146\151\147\x2e\152\163\157\x6e");
    echo json_encode($Aq, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    die;
}
function mo_get_configuration_array($df)
{
    $Rd = Utilities::getVariableNames($df);
    $oj = array();
    foreach ($Rd as $p1 => $OK) {
        $rU = variable_get($OK);
        if (!$rU) {
            goto PD;
        }
        $oj[$p1] = $rU;
        PD:
        ai:
    }
    I2:
    return $oj;
}
function miniorange_import_Config()
{
    if (!empty($_FILES["\x66\151\154\x65\x73"]["\x74\155\x70\137\156\x61\x6d\145"]["\x6d\x6f\x5f\x69\x6d\160\157\162\x74\x5f\x43\x6f\156\x66\151\x67\x5f\146\x69\154\x65"])) {
        goto y2;
    }
    drupal_set_message(t("\x3c\142\x20\x73\x74\171\x6c\145\x3d\x22\143\x6f\x6c\x6f\x72\72\40\x72\145\x64\42\x3e\120\x6c\x65\141\163\x65\40\x73\x65\154\x65\x63\x74\40\x66\x69\x6c\x65\x20\x66\151\162\x73\164\x20\x74\157\x20\x75\x70\x6c\x6f\141\x64\40\103\157\x6e\x66\151\x67\165\x72\141\164\x69\157\156\x21\x3c\57\x62\x3e"), "\145\x72\162\157\162");
    goto n8;
    y2:
    $Hd = $_FILES["\146\151\154\145\163"]["\156\x61\x6d\145"]["\x6d\x6f\137\x69\155\x70\157\x72\x74\x5f\103\157\x6e\x66\x69\x67\x5f\146\x69\x6c\x65"];
    list($r2, $d5) = explode("\x2e", $Hd);
    if ($d5 == "\x6a\163\157\156") {
        goto Mf;
    }
    drupal_set_message(t("\x3c\x62\x20\163\164\171\154\145\x3d\x22\x63\x6f\x6c\x6f\x72\x3a\40\x72\145\144\42\76\x46\x69\x6c\x65\40\x74\x79\x70\145\x20\x69\x73\x20\156\157\x74\40\143\x6f\155\160\x61\164\151\x62\154\145\x3c\x2f\142\76\40\x3c\x62\162\76\40\120\x6c\145\x61\163\x65\40\x53\x65\154\x65\143\164\40\x3c\x62\x20\163\164\x79\154\x65\75\42\143\x6f\154\x6f\x72\x3a\x20\162\x65\x64\42\x3e\42\x2e\x6a\163\x6f\156\42\x3c\x2f\x62\76\40\x65\170\x74\x65\x6e\144\x65\x64\40\146\x69\x6c\145\x20\x74\157\40\x75\160\154\x6f\x61\144\40\x43\157\156\x66\151\147\x75\x72\x61\164\x69\x6f\x6e\41"), "\x65\x72\x72\x6f\162");
    goto Zc;
    Mf:
    $Hd = @file_get_contents($_FILES["\146\151\154\x65\x73"]["\x74\155\160\x5f\x6e\141\155\x65"]["\x6d\x6f\137\x69\x6d\160\157\162\x74\137\103\157\x6e\x66\x69\147\137\146\x69\154\145"]);
    $Aq = json_decode($Hd, true);
    mo_update_configuration_array($Aq);
    Zc:
    n8:
}
function mo_update_configuration_array($Aq)
{
    global $base_url;
    $r3 = array("\111\104\x50\x5f\115\145\x74\141\144\141\x74\141" => "\x6d\x6f\137\157\160\164\x69\157\x6e\x73\x5f\145\156\165\155\x5f\x69\x64\x65\x6e\x74\151\x74\171\137\x70\162\x6f\x76\x69\144\145\162", "\x53\145\x72\x76\151\143\x65\137\x50\162\157\x76\x69\144\145\162" => "\155\x6f\x5f\x6f\160\x74\151\157\156\163\137\x65\x6e\x75\x6d\137\x73\145\x72\x76\151\x63\145\x5f\x70\162\x6f\x76\151\144\x65\162", "\101\164\x74\162\x69\142\x75\x74\x65\x5f\x4d\x61\x70\160\151\156\x67" => "\155\x6f\x5f\x6f\160\164\151\157\x6e\163\x5f\141\164\x74\x72\x69\142\x75\164\145\x5f\155\x61\160\160\151\x6e\x67", "\x53\151\x67\156\137\x49\156\137\x53\145\164\164\x69\156\147\163" => "\155\157\x5f\x6f\160\164\x69\x6f\x6e\x73\x5f\x73\151\147\156\151\x6e\137\x73\x65\x74\x74\x6e\147\163", "\103\165\163\164\x6f\x6d\137\x43\145\162\x74\151\x66\x69\x63\141\x74\145" => "\155\157\137\x6f\x70\164\x69\157\x6e\163\137\x63\165\x73\x74\x6f\x6d\137\143\145\162\164\x69\146\151\143\x61\164\145");
    foreach ($r3 as $O3 => $df) {
        foreach ($Aq[$O3] as $p1 => $OK) {
            $kP = Utilities::getVariableNames($df);
            $kP = $kP[$p1];
            if (!(!empty($kP) && !empty($OK))) {
                goto Dp;
            }
            variable_set($kP, $OK);
            Dp:
            Bn:
        }
        G_:
        Hu:
    }
    sY:
    $Ql = "\x43\117\116\106\111\x47\x55\122\101\124\111\117\116\137\123\101\126\x45\104";
    variable_set("\155\151\x6e\151\x6f\x72\141\x6e\147\145\x5f\143\x6f\x6e\146\x69\x67\137\163\164\x61\x74\165\163", $Ql);
    drupal_set_message(t("\x59\x6f\x75\x72\x20\103\157\x6e\146\x69\147\165\162\x61\x74\x69\x6f\x6e\x20\x61\162\x65\x20\163\165\143\x63\x65\163\163\146\165\154\x6c\171\x20\151\x6d\x70\x6f\162\x74\145\144\56"));
    drupal_goto($base_url . "\x2f\x61\144\x6d\151\x6e\x2f\x63\x6f\x6e\146\151\x67\57\x70\145\157\160\x6c\145\57\155\151\156\151\x6f\162\141\156\x67\145\137\x73\141\x6d\x6c\x5f\151\144\160\x2f\x69\x64\x70\x5f\163\145\x74\x75\160");
}
function mo_get_version_informations()
{
    $In = array();
    $In["\120\x48\x50\137\x76\x65\162\163\151\157\x6e"] = phpversion();
    $In["\104\162\165\x70\x61\154\137\166\x65\x72\163\x69\x6f\x6e"] = VERSION;
    $In["\117\120\105\116\137\x53\x53\x4c"] = mo_saml_is_openssl_installed();
    $In["\x43\x55\122\x4c"] = mo_saml_is_curl_installed();
    $In["\x49\x43\x4f\x4e\x56"] = mo_saml_is_iconv_installed();
    $In["\104\117\115"] = mo_saml_is_dom_installed();
    return $In;
}
function mo_saml_is_openssl_installed()
{
    if (in_array("\157\160\x65\156\163\x73\x6c", get_loaded_extensions())) {
        goto v5;
    }
    return 0;
    goto dz;
    v5:
    return 1;
    dz:
}
function mo_saml_is_curl_installed()
{
    if (in_array("\143\165\x72\x6c", get_loaded_extensions())) {
        goto mU;
    }
    return 0;
    goto Ar;
    mU:
    return 1;
    Ar:
}
function mo_saml_is_iconv_installed()
{
    if (in_array("\151\143\x6f\156\x76", get_loaded_extensions())) {
        goto mJ;
    }
    return 0;
    goto Hq;
    mJ:
    return 1;
    Hq:
}
function mo_saml_is_dom_installed()
{
    if (in_array("\144\157\155", get_loaded_extensions())) {
        goto b6;
    }
    return 0;
    goto Bt;
    b6:
    return 1;
    Bt:
}