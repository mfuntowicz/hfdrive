using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HfDrive.Protocol;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;

namespace HfDrive.Desktop.Interop;

/// <summary>Short-lived form input becomes a bound current-user ciphertext before IPC.</summary>
internal static class PublicationCredentialProtection
{
    public static SetPublicationCredentialsRequest CreateRequest(
        PublicationProtectionContext context, Guid operationId, string keyId, string secretKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentException.ThrowIfNullOrEmpty(secretKey);
        if (keyId.Length > 1024 || secretKey.Length > 1024)
            throw new ArgumentException("A supplemental credential field exceeds its size limit.");
        try
        {
            var utf8 = new UTF8Encoding(false, true);
            _ = utf8.GetByteCount(keyId);
            _ = utf8.GetByteCount(secretKey);
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException("Credential text is not valid Unicode.");
        }
        byte[] publicContext = ProtocolJson.SerializeCanonical(context);
        if (publicContext.Length > 16 * 1024)
            throw new ArgumentException("The credential binding exceeds its size limit.");
        // Reserve worst-case JSON escaping plus writer headroom, avoiding secret-buffer growth/copies.
        var plaintext = new ArrayBufferWriter<byte>(checked(publicContext.Length + 6 * (keyId.Length + secretKey.Length) + 4096));
        try
        {
            using (var writer = new Utf8JsonWriter(plaintext))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("context");
                writer.WriteRawValue(publicContext);
                writer.WriteString("key_id", keyId);
                writer.WriteString("secret_key", secretKey);
                writer.WriteEndObject();
            }
            return new SetPublicationCredentialsRequest
            {
                OperationId = operationId,
                ConnectionId = context.ConnectionId,
                ProtectedCredentials = Protect(plaintext.WrittenSpan, context.Entropy(operationId)),
            };
        }
        finally
        {
            // Clear wipes the written backing-buffer bytes; immutable UI strings cannot promise erasure.
            plaintext.Clear();
        }
    }

    private static unsafe string Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy)
    {
        fixed (byte* data = plaintext)
        fixed (byte* extra = entropy)
        {
            CRYPT_INTEGER_BLOB input = new() { cbData = checked((uint)plaintext.Length), pbData = data };
            CRYPT_INTEGER_BLOB optionalEntropy = new() { cbData = checked((uint)entropy.Length), pbData = extra };
            CRYPT_INTEGER_BLOB output = default;
            if (!PInvoke.CryptProtectData(&input, null, &optionalEntropy, null, null,
                PInvoke.CRYPTPROTECT_UI_FORBIDDEN, &output))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Current-user credential protection failed.");
            try
            {
                return Convert.ToBase64String(new ReadOnlySpan<byte>(output.pbData, checked((int)output.cbData)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(new Span<byte>(output.pbData, checked((int)output.cbData)));
                PInvoke.LocalFree(new HLOCAL(output.pbData));
            }
        }
    }
}
