using System.Text;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>Typed models must serialize exactly like the Rust codec.</summary>
public sealed class TypedSerializationTests
{
    [Fact]
    public void U64_Fields_Are_Canonical_Decimal_Strings()
    {
        var request = new SubscribeStatusRequest { LastSequence = ulong.MaxValue };
        var bytes = ProtocolJson.SerializeCanonical(request);
        var text = Encoding.UTF8.GetString(bytes);
        Assert.Equal("{\"last_sequence\":\"18446744073709551615\"}", text);

        var result = new FreeSpaceResult { FreedBytes = 0, DehydratedFiles = 3 };
        Assert.Equal("{\"dehydrated_files\":3,\"freed_bytes\":\"0\"}", Encoding.UTF8.GetString(ProtocolJson.SerializeCanonical(result)));
    }

    [Fact]
    public void U64_Rejects_Non_Canonical_Decimal_Strings()
    {
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64(""));
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64("00"));
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64("01"));
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64("+1"));
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64("-1"));
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64("1.0"));
        Assert.Throws<ProtocolException>(() => ProtocolJson.ParseDecimal64("18446744073709551616"));
        Assert.Equal(0ul, ProtocolJson.ParseDecimal64("0"));
        Assert.Equal(ulong.MaxValue, ProtocolJson.ParseDecimal64("18446744073709551615"));
    }

    [Fact]
    public void Optional_Fields_Are_Omitted_Not_Null()
    {
        var request = new StartLoginRequest
        {
            OperationId = Guid.Parse("22222222-2222-4222-8222-222222222222"),
            Flow = LoginFlow.Pkce,
            Purpose = LoginPurpose.Signin,
        };
        var text = Encoding.UTF8.GetString(ProtocolJson.SerializeCanonical(request));
        Assert.DoesNotContain("organization_id", text, StringComparison.Ordinal);
        Assert.DoesNotContain("null", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Enum_Members_Use_Snake_Case_Wire_Names()
    {
        var request = new GetStatusRequest();
        var envelope = Envelope.Request(Guid.Parse("11111111-1111-4111-8111-111111111111"), "get_status", request);
        var text = Encoding.UTF8.GetString(envelope.ToCanonicalBytes());
        Assert.Equal("{\"body\":{},\"kind\":\"request\",\"method\":\"get_status\",\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"11111111-1111-4111-8111-111111111111\"}", text);

        var login = new StartLoginRequest
        {
            OperationId = Guid.Parse("22222222-2222-4222-8222-222222222222"),
            Flow = LoginFlow.Device,
            Purpose = LoginPurpose.WriteStorage,
        };
        var loginText = Encoding.UTF8.GetString(ProtocolJson.SerializeCanonical(login));
        Assert.Contains("\"flow\":\"device\"", loginText, StringComparison.Ordinal);
        Assert.Contains("\"purpose\":\"write_storage\"", loginText, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_Members_And_Enum_Values_Are_Rejected()
    {
        var unknownMember = Encoding.UTF8.GetBytes("{\"accepted\":true,\"extra\":1}");
        Assert.Throws<ProtocolException>(() => ProtocolJson.Deserialize<CancelRequestResult>(unknownMember));

        var unknownEnum = Encoding.UTF8.GetBytes("{\"protocol_major\":1,\"protocol_minor\":0,\"role\":\"superuser\",\"build_version\":\"1\"}");
        Assert.Throws<ProtocolException>(() => ProtocolJson.Deserialize<HelloRequest>(unknownEnum));

        var numberForString = Encoding.UTF8.GetBytes("{\"last_sequence\":7}");
        Assert.Throws<ProtocolException>(() => ProtocolJson.Deserialize<SubscribeStatusRequest>(numberForString));
    }

    [Fact]
    public void Envelope_Canonical_Order_Is_Major_Minor_RequestId_Kind_Method_Body()
    {
        var envelope = Envelope.ResponseError(
            Guid.Parse("33333333-3333-4333-8333-333333333333"),
            "get_status",
            new ProtocolError { Code = ProtocolErrorCode.Busy, Message = "retry", RetryAfterMs = 50 });
        var text = Encoding.UTF8.GetString(envelope.ToCanonicalBytes());
        Assert.Equal(
            "{\"body\":{\"error\":{\"code\":\"busy\",\"message\":\"retry\",\"retry_after_ms\":\"50\"}},"
            + "\"kind\":\"response\",\"method\":\"get_status\",\"protocol_major\":1,\"protocol_minor\":0,"
            + "\"request_id\":\"33333333-3333-4333-8333-333333333333\"}",
            text);
    }

    [Fact]
    public void Credential_Request_Debug_And_Log_Are_Redacted()
    {
        var request = new SetPublicationCredentialsRequest
        {
            OperationId = Guid.Parse("55555555-5555-4555-8555-555555555555"),
            ConnectionId = Guid.Parse("66666666-6666-4666-8666-666666666666"),
            ProtectedCredentials = "MARKER-PROTECTED-SECRET-DO-NOT-LOG",
        };
        Assert.DoesNotContain("MARKER-PROTECTED-SECRET-DO-NOT-LOG", request.ToString(), StringComparison.Ordinal);

        var envelope = Envelope.Request(Guid.Parse("44444444-4444-4444-8444-444444444444"), "set_publication_credentials", request);
        Assert.DoesNotContain("MARKER-PROTECTED-SECRET-DO-NOT-LOG", envelope.DescribeForLog(), StringComparison.Ordinal);
    }

    [Fact]
    public void Response_Carries_Exactly_One_Of_Result_Or_Error()
    {
        var ok = Envelope.Response(
            Guid.Parse("77777777-7777-4777-8777-777777777777"),
            "get_status",
            new GetStatusResult { EventSequence = 7, Account = AccountStatus.SignedOut });
        Assert.True(ok.Body.TryGetProperty("result", out _));
        Assert.False(ok.Body.TryGetProperty("error", out _));
        Assert.Equal("{\"account\":{\"state\":\"signed_out\"},\"connections\":[],\"event_sequence\":\"7\"}", Encoding.UTF8.GetString(ProtocolJson.SerializeCanonical(ok.GetResult<GetStatusResult>())));

        var errorEnvelope = Envelope.ResponseError(
            Guid.Parse("77777777-7777-4777-8777-777777777777"),
            "get_status",
            new ProtocolError { Code = ProtocolErrorCode.Busy, Message = "retry", RetryAfterMs = 50 });
        var error = errorEnvelope.GetError();
        Assert.Equal(ProtocolErrorCode.Busy, error.Code);
        Assert.Equal(50ul, error.RetryAfterMs);
    }

    [Fact]
    public void StatusDisplayText_Matches_The_Contract_Wording()
    {
        Assert.Equal("Up to date", StatusDisplayText.Get(ConnectionState.UpToDate));
        Assert.Equal("Pending upload", StatusDisplayText.Get(ConnectionState.PendingUpload));
        Assert.Equal("Uploading", StatusDisplayText.Get(ConnectionState.Uploading));
        Assert.Equal("Publishing changes", StatusDisplayText.Get(ConnectionState.PublishingChanges));
        Assert.Equal("Downloading", StatusDisplayText.Get(ConnectionState.Downloading));
        Assert.Equal("Offline", StatusDisplayText.Get(ConnectionState.Offline));
        Assert.Equal("Needs sign-in", StatusDisplayText.Get(ConnectionState.NeedsSignIn));
        Assert.Equal("Storage setup required", StatusDisplayText.Get(ConnectionState.StorageSetupRequired));
        Assert.Equal("Permission denied", StatusDisplayText.Get(ConnectionState.PermissionDenied));
        Assert.Equal("Conflict", StatusDisplayText.Get(ConnectionState.Conflict));
        Assert.Equal("Disk full", StatusDisplayText.Get(ConnectionState.DiskFull));
        Assert.Equal("Write sync paused", StatusDisplayText.Get(ConnectionState.WriteSyncPaused));
    }

    [Fact]
    public void Error_Code_Wire_Names_Match_The_Contract()
    {
        Assert.Equal("needs_sign_in", ProtocolErrorCodeConverter.CodeToWire(ProtocolErrorCode.NeedsSignIn));
        Assert.Equal("provider_in_other_session", ProtocolErrorCodeConverter.CodeToWire(ProtocolErrorCode.ProviderInOtherSession));
        Assert.Equal("frame_too_large", ProtocolErrorCodeConverter.CodeToWire(ProtocolErrorCode.FrameTooLarge));
        Assert.Equal(ProtocolErrorCode.VersionMismatch, ProtocolErrorCodeConverter.WireToCode("version_mismatch"));
        Assert.Throws<ProtocolException>(() => ProtocolErrorCodeConverter.WireToCode("nope"));
    }
}
