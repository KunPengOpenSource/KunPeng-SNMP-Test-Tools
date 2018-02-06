using System;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Qishi_Tester
{
    /// <summary>
    /// 文本消息框控件
    /// </summary>
    public partial class NewTextBox : TextBox
    {
        public NewTextBox()
        {
            InitializeComponent();        
        }

        #region 公开属性

        /// <summary>
        /// 消息体滚动框
        /// </summary>
        public ScrollViewer ScrollViewer { get; set; }

        /// <summary>
        /// 滚动框背景
        /// </summary>
        public Brush ScrollViewerBackground
        {
            get { return (Brush)GetValue(ScrollViewerBackgroundProperty); }
            set { SetValue(ScrollViewerBackgroundProperty, value); }
        }
        public static readonly DependencyProperty ScrollViewerBackgroundProperty =
            DependencyProperty.Register("ScrollViewerBackground", typeof(Brush), typeof(NewTextBox), new PropertyMetadata(Brushes.LightBlue));

        /// <summary>
        /// 滚动条前景
        /// </summary>
        public Brush ScrollBarForeground
        {
            get { return (Brush)GetValue(ScrollBarForegroundProperty); }
            set { SetValue(ScrollBarForegroundProperty, value); }
        }
        public static readonly DependencyProperty ScrollBarForegroundProperty =
            DependencyProperty.Register("ScrollBarForeground", typeof(Brush), typeof(NewTextBox), new PropertyMetadata(Brushes.RoyalBlue));

        /// <summary>
        /// 滚动条背景
        /// </summary>
        public Brush ScrollBarBackground
        {
            get { return (Brush)GetValue(ScrollBarBackgroundProperty); }
            set { SetValue(ScrollBarBackgroundProperty, value); }
        }
        public static readonly DependencyProperty ScrollBarBackgroundProperty =
            DependencyProperty.Register("ScrollBarBackground", typeof(Brush), typeof(NewTextBox), new PropertyMetadata(Brushes.WhiteSmoke));

        #endregion

        #region 界面交互

        // 初始化滚动条
        private void PART_ContentHost_Initialized(object sender, EventArgs e)
        {
            ScrollViewer = sender as ScrollViewer;
            _ScrollYAction = ScrollYMethod;
            _ScrollXAction = ScrollXMethod;
        }

        // 鼠标滚轮
        private void PART_ContentHost_MouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
        {
            ScrollViewer.ScrollToVerticalOffset(ScrollViewer.VerticalOffset - (e.Delta >> 2));
        }

        // 文本内容改变
        private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (this.Text != "" && ScrollViewer != null)
            {
                // 如果已经拖到最底端，则固定住
                if (ScrollViewer.ScrollableHeight == ScrollViewer.VerticalOffset)
                    ScrollViewer.ScrollToBottom();
            }
        }

        // 坚向位移
        private double _ScrollY
        {
            get { return _scrollY; }
            set
            {
                _scrollY = value;
                // 开启滚动
                if (_scrollY != 0 && (_ScrollYResult == null || _ScrollYResult.IsCompleted))
                    _ScrollYResult = _ScrollYAction.BeginInvoke(null, null);
            }
        }
        private double _scrollY;

        // 横向位移
        private double _ScrollX
        {
            get { return _scrollX; }
            set
            {
                _scrollX = value;
                // 开启滚动
                if (_scrollX != 0 && (_ScrollXResult == null || _ScrollXResult.IsCompleted))
                    _ScrollXResult = _ScrollXAction.BeginInvoke(null, null);
            }
        }
        private double _scrollX;

        // 文本选中滚动位移计算
        private void TextBox_SelectionChanged(object sender, RoutedEventArgs e)
        {
            if (ScrollViewer != null && this.SelectedText != "")
            {
                var point = System.Windows.Input.Mouse.GetPosition(ScrollViewer);
                // 纵向位移
                double y = point.Y;
                if (y > 0)
                {
                    y = y - ScrollViewer.ActualHeight;
                    if (y < 0) y = 0;
                }
                _ScrollY = y;
                // 横向位移
                double x = point.X;
                if (x > 0)
                {
                    x = x - ScrollViewer.ActualWidth;
                    if (x < 0) x = 0;
                }
                _ScrollX = x;
            }
        }

        // 竖向滚动
        private Action _ScrollYAction;
        private IAsyncResult _ScrollYResult;
        private void ScrollYMethod()
        {
            double endOffset = 0;
            if (_ScrollY < 0)       // 向上滚动
                endOffset = 0;
            else                    // 向下滚动
                ScrollViewer.Dispatcher.Invoke((Action)(() => endOffset = ScrollViewer.ScrollableHeight), null);
            // 初始位置
            double offset = 0;
            ScrollViewer.Dispatcher.Invoke((Action)(() => offset = ScrollViewer.VerticalOffset), null);
            // 开始滚动
            while (offset != endOffset && _ScrollY != 0)
            {
                ScrollViewer.Dispatcher.Invoke((Action)(() =>
                {
                    offset = ScrollViewer.VerticalOffset;
                    ScrollViewer.ScrollToVerticalOffset(ScrollViewer.VerticalOffset + _ScrollY);
                }), null);
                Thread.Sleep(100);
            }
        }

        // 横向滚动
        private Action _ScrollXAction;
        private IAsyncResult _ScrollXResult;
        private void ScrollXMethod()
        {
            double endOffset = 0;
            if (_ScrollX < 0)       // 向左滚动
                endOffset = 0;
            else                    // 向右滚动
                ScrollViewer.Dispatcher.Invoke((Action)(() => endOffset = ScrollViewer.ScrollableWidth), null);
            // 初始位置
            double offset = 0;
            ScrollViewer.Dispatcher.Invoke((Action)(() => offset = ScrollViewer.HorizontalOffset), null);
            // 开始滚动
            while (offset != endOffset && _ScrollX != 0)
            {
                ScrollViewer.Dispatcher.Invoke((Action)(() =>
                {
                    offset = ScrollViewer.HorizontalOffset;
                    ScrollViewer.ScrollToHorizontalOffset(ScrollViewer.HorizontalOffset + _ScrollX);
                }), null);
                Thread.Sleep(100);
            }
        }

        // 清空消息栏
        private void BTN_Clear_Click(object sender, RoutedEventArgs e)
        {
            this.Text = "";
        }

        // 关闭消息栏
        private void BTN_Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        #endregion

        #region 公开方法

        /// <summary>
        /// 关闭消息框
        /// </summary>
        public void Close()
        {
            ThreadPool.QueueUserWorkItem((c) =>
            {
                for (int i = 1; i < 11; i++)
                {
                    this.Dispatcher.Invoke((Action)(() => this.Opacity = 1 - i / 10.0));
                    Thread.Sleep(50);
                }
                this.Dispatcher.Invoke((Action)(() => this.Visibility = Visibility.Collapsed));
            });
        }

        /// <summary>
        /// 显示消息框
        /// </summary>
        public void Show()
        {
            if (this.Visibility != Visibility.Visible)
            {
                this.Visibility = Visibility.Visible;
                ThreadPool.QueueUserWorkItem((c) =>
                {
                    for (int i = 1; i < 10; i++)
                    {
                        this.Dispatcher.Invoke((Action)(() => this.Opacity = i / 10.0));
                        Thread.Sleep(50);
                    }
                    this.Dispatcher.Invoke((Action)(() => this.Opacity = 1));
                });
            }
        }

        #endregion
    }
}
