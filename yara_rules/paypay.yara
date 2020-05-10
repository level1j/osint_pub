rule paypay_title
{
    strings:
        $html_title = "<title>PayPay本人確認</title>"
    condition:
        $html_title
}
