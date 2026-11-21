<#--
  SMS / Email OTP page for the accessibility fallback tier.
  Accessibility: real <button>s and <label>s, no CAPTCHA, no countdown that blocks the user,
  inputmode="numeric" + autocomplete="one-time-code" so OS autofill and screen readers work,
  errors announced via the theme's aria-live message area.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">
    <#if bridgeStage == "verify">Enter your verification code<#elseif bridgePurpose == "enrolment">Verify your identity to set up MFA<#else>Choose how to receive your code</#if>
  <#elseif section = "form">
    <#if bridgeStage == "verify">
      <p id="otp-help">
        We sent a 6-digit code by <#if sentChannel == "sms">text message<#else>email</#if> to <strong>${sentTo}</strong>.
        The code is valid for 5 minutes.
      </p>
      <form id="kc-bridge-otp-verify" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        <div class="${properties.kcFormGroupClass!}">
          <label for="otp" class="${properties.kcLabelClass!}">Verification code</label>
          <input id="otp" name="otp" type="text" class="${properties.kcInputClass!}"
                 inputmode="numeric" pattern="[0-9 ]*" maxlength="8" autocomplete="one-time-code"
                 aria-describedby="otp-help" autofocus required/>
        </div>
        <div class="${properties.kcFormGroupClass!}">
          <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                  type="submit" name="action" value="verify">Verify</button>
        </div>
      </form>
      <form id="kc-bridge-otp-resend" action="${url.loginAction}" method="post">
        <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}"
                type="submit" name="action" value="resend" formnovalidate>Send a new code</button>
        <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}"
                type="submit" name="action" value="change" formnovalidate>Use a different method</button>
      </form>
    <#else>
      <#if bridgePurpose == "enrolment">
        <p>Before you set up your authenticator, confirm it is really you with a one-time code sent to the contact details on file.</p>
      <#else>
        <p>Your account uses a one-time code as its second factor. Choose where we should send it.</p>
      </#if>
      <form id="kc-bridge-otp-choose" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        <input type="hidden" name="action" value="send"/>
        <#if hasMobile>
          <div class="${properties.kcFormGroupClass!}">
            <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                    type="submit" name="channel" value="sms">Text message to ${maskedMobile}</button>
          </div>
        </#if>
        <#if hasEmail>
          <div class="${properties.kcFormGroupClass!}">
            <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}"
                    type="submit" name="channel" value="email">Email to ${maskedEmail}</button>
          </div>
        </#if>
      </form>
      <p>Did not request this sign-in? Close this page and report it to the IT service desk.</p>
    </#if>
  </#if>
</@layout.registrationLayout>
