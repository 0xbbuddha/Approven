package com.approven.app

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// Sampled straight from the logo so the app and its icon match.
val Mint = Color(0xFF24F694)
val Amber = Color(0xFFFFC145)
val Coral = Color(0xFFFF5C6C)
val Ink = Color(0xFF000000)
val Card = Color(0xFF111413)
val CardHigh = Color(0xFF1A1F1D)
val Muted = Color(0xFF8A938F)

@Composable
fun ApprovenTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Mint,
            onPrimary = Ink,
            background = Ink,
            onBackground = Color.White,
            surface = Ink,
            onSurface = Color.White,
            surfaceVariant = Card,
            onSurfaceVariant = Muted,
            error = Coral,
            outline = CardHigh,
        ),
    ) {
        Box(Modifier.fillMaxSize().background(Ink)) { content() }
    }
}

/** "appro" in white, "ven" in mint, the same split as the logo's wordmark. */
@Composable
fun Wordmark(size: Int = 28) {
    Text(
        buildAnnotatedString {
            withStyle(SpanStyle(color = Color.White)) { append("appro") }
            withStyle(SpanStyle(color = Mint)) { append("ven") }
        },
        fontSize = size.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.5).sp,
    )
}

/**
 * The logo with expanding rings behind it. [color] tints the rings,
 * [active] decides whether they pulse at all - an idle logo is dimmed
 * so "offline" reads at a glance without any text.
 */
@Composable
fun PulsingLogo(color: Color, active: Boolean, size: Dp = 180.dp) {
    val t = rememberInfiniteTransition(label = "pulse")
    val wave by t.animateFloat(0f, 1f, infiniteRepeatable(tween(2200, easing = LinearEasing)), label = "wave")
    val breathe by t.animateFloat(
        0.96f, 1.04f,
        infiniteRepeatable(tween(1100, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "breathe",
    )
    Box(Modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            // Rings grow from the disc's edge to the box's edge, never past it.
            val base = this.size.minDimension * 0.3f
            drawCircle(color.copy(alpha = 0.10f), radius = base * 1.25f)
            if (active) {
                for (offset in listOf(0f, 0.5f)) {
                    val p = (wave + offset) % 1f
                    drawCircle(
                        color.copy(alpha = (1f - p) * 0.5f),
                        radius = base * (1.25f + p * 0.4f),
                        style = Stroke(width = 3.dp.toPx()),
                    )
                }
            }
        }
        Image(
            painterResource(R.drawable.logo_mark),
            contentDescription = null,
            modifier = Modifier
                .size(size * 0.55f)
                .scale(if (active) breathe else 1f)
                .alpha(if (active) 1f else 0.35f),
        )
    }
}

@Composable
fun Panel(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(Card)
            .padding(20.dp),
        content = content,
    )
}
