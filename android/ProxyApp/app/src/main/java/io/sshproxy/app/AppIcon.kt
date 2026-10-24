package io.sshproxy.app

import android.content.Context
import android.graphics.Bitmap
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmapOrNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * In-memory cache of decoded application launcher icons.
 *
 * Decoding is expensive and the routing list may hold hundreds of entries, so every icon is
 * decoded once off the main thread and reused afterwards.
 */
object AppIconCache {
    // Pixel budget instead of an entry count: a 40dp icon costs ~25 KB at xxhdpi and ~100 KB at
    // xxxhdpi, so a fixed entry count would either waste memory or evict icons too early.
    private const val MAX_CACHE_KB = 8 * 1024

    // android.util.LruCache is not thread safe, so every access goes through synchronized(cache).
    private val cache = object : LruCache<String, ImageBitmap>(MAX_CACHE_KB) {
        override fun sizeOf(key: String, value: ImageBitmap): Int =
            (value.asAndroidBitmap().byteCount / 1024).coerceAtLeast(1)
    }

    suspend fun load(context: Context, packageName: String, sizePx: Int): ImageBitmap? {
        if (sizePx <= 0) {
            return null
        }
        val key = "$packageName@$sizePx"
        synchronized(cache) {
            cache.get(key)?.let { return it }
        }

        return withContext(Dispatchers.IO) {
            val drawable = runCatching {
                context.packageManager.getApplicationIcon(packageName)
            }.getOrNull() ?: return@withContext null

            // toBitmapOrNull is required here: adaptive icons report an intrinsic size of -1,
            // which makes the non-null toBitmap() overload throw.
            val bitmap = drawable.toBitmapOrNull(sizePx, sizePx, Bitmap.Config.ARGB_8888)
                ?: return@withContext null

            bitmap.asImageBitmap().also {
                synchronized(cache) {
                    cache.put(key, it)
                }
            }
        }
    }
}

/**
 * Draws the launcher icon of an installed application.
 *
 * The icon is decoded asynchronously; an empty placeholder is shown until it becomes available.
 */
@Composable
fun AppIcon(
    packageName: String,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    val context = LocalContext.current
    val sizePx = with(LocalDensity.current) { size.roundToPx() }

    val bitmap by produceState<ImageBitmap?>(initialValue = null, packageName, sizePx) {
        value = AppIconCache.load(context, packageName, sizePx)
    }

    val current = bitmap
    if (current != null) {
        Image(
            bitmap = current,
            contentDescription = null,
            modifier = modifier.size(size),
        )
    } else {
        Box(modifier = modifier.size(size))
    }
}
