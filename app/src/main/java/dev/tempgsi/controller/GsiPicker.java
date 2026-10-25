package dev.tempgsi.controller;

import android.app.Activity;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.Window;
import android.view.WindowManager;
import android.widget.*;

final class GsiPicker {
    static void show(Activity activity,String selected,Runnable prepared,Runnable browse){
        Dialog dialog=new Dialog(activity);dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        ScrollView scroll=new ScrollView(activity);scroll.setVerticalScrollBarEnabled(false);scroll.setClipToPadding(false);
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);
        int pad=Ui.dp(activity,24);body.setPadding(pad,Ui.dp(activity,12),pad,pad);
        GradientDrawable background=Ui.shape(activity,Ui.BG,32);background.setStroke(Ui.dp(activity,1),0x20ffffff);body.setBackground(background);
        LinearLayout handleRow=new LinearLayout(activity);handleRow.setGravity(Gravity.CENTER);
        android.view.View handle=new android.view.View(activity);handle.setBackground(Ui.shape(activity,0xff626878,4));
        handleRow.addView(handle,new LinearLayout.LayoutParams(Ui.dp(activity,36),Ui.dp(activity,4)));body.addView(handleRow,new LinearLayout.LayoutParams(-1,Ui.dp(activity,16)));
        Ui.space(body,12);TextView title=Ui.text(body,"Select GSI",25,Ui.TEXT);title.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));
        TextView current=Ui.text(body,selected==null?"No image selected":"Selected: "+selected,13,Ui.MUTED);current.setMaxLines(2);current.setEllipsize(android.text.TextUtils.TruncateAt.END);Ui.space(body,22);

        if(!HostIdentity.isPd2425(android.os.Build.DEVICE)){
        LinearLayout existing=Ui.card(body);row(existing,activity,"Prepared EvoX","Android 16 · Galaxy S23",true);
        Ui.button(existing,"Use prepared image",true,()->{dialog.dismiss();prepared.run();});
        }
        Ui.space(body,6);
        LinearLayout file=Ui.card(body);row(file,activity,"Image file","Import a raw ext4 .img",false);
        Ui.button(file,"Browse files",false,()->{dialog.dismiss();browse.run();});
        Ui.space(body,4);
        scroll.addView(body,new ScrollView.LayoutParams(-1,-2));dialog.setContentView(scroll);dialog.setCanceledOnTouchOutside(true);
        Window window=dialog.getWindow();
        if(window!=null){
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            WindowManager.LayoutParams attributes=window.getAttributes();attributes.gravity=Gravity.BOTTOM;attributes.dimAmount=.55f;window.setAttributes(attributes);
            int style=activity.getResources().getIdentifier("GsiSheetAnimation","style",activity.getPackageName());window.setWindowAnimations(style);window.setNavigationBarColor(Ui.BG);
        }
        dialog.setOnShowListener(v->{if(window!=null){int max=(int)(activity.getResources().getDisplayMetrics().heightPixels*.82f);body.measure(android.view.View.MeasureSpec.makeMeasureSpec(activity.getResources().getDisplayMetrics().widthPixels,android.view.View.MeasureSpec.EXACTLY),android.view.View.MeasureSpec.makeMeasureSpec(0,android.view.View.MeasureSpec.UNSPECIFIED));window.setLayout(-1,Math.min(body.getMeasuredHeight(),max));}Ui.reveal(body);});
        dialog.show();
    }
    private static void row(LinearLayout parent,Activity activity,String title,String subtitle,boolean logo){
        LinearLayout row=new LinearLayout(activity);row.setGravity(Gravity.CENTER_VERTICAL);
        ImageView icon=new ImageView(activity);icon.setBackground(Ui.shape(activity,logo?Color.BLACK:0xff30394e,18));icon.setClipToOutline(true);
        if(logo){icon.setImageResource(activity.getResources().getIdentifier("brand_logo","drawable",activity.getPackageName()));icon.setScaleType(ImageView.ScaleType.FIT_CENTER);}
        else{icon.setImageResource(activity.getResources().getIdentifier("ic_image_file","drawable",activity.getPackageName()));icon.setPadding(Ui.dp(activity,13),Ui.dp(activity,13),Ui.dp(activity,13),Ui.dp(activity,13));}
        row.addView(icon,new LinearLayout.LayoutParams(Ui.dp(activity,56),Ui.dp(activity,56)));
        LinearLayout labels=new LinearLayout(activity);labels.setOrientation(LinearLayout.VERTICAL);labels.setPadding(Ui.dp(activity,16),0,0,0);
        TextView heading=Ui.text(labels,title,18,Ui.TEXT);heading.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));Ui.text(labels,subtitle,13,Ui.MUTED);
        row.addView(labels,new LinearLayout.LayoutParams(0,-2,1));parent.addView(row,new LinearLayout.LayoutParams(-1,-2));
    }
    private GsiPicker(){}
}
